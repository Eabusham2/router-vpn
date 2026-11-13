#!/usr/bin/env python3
"""Validate the typed desktop parent and retained original lifecycle at an exact SHA."""
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

# All execution, parsing and original capture cases come from the trusted checkout.
CAPTURE_PATH = Path(__file__).resolve().with_name("test_focused_desktop_socks_capture.py")
_spec = importlib.util.spec_from_file_location("routervpn_parent_capture_gate", CAPTURE_PATH)
if _spec is None or _spec.loader is None:
    raise RuntimeError("trusted original desktop capture gate is missing")
CAPTURE = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = CAPTURE
_spec.loader.exec_module(CAPTURE)
CORE, CORE_PATH, Case = CAPTURE.CORE, CAPTURE.CORE_PATH, CAPTURE.Case
SUITE = "desktop-socks-parent"
GROUPS = {
    "typed-selection": {
        "TestDesktopNodeChainSOCKSSelectionRetainsTypedSources": [
            "wg",
            "awg2-fast",
            "awg2-strong"
        ],
        "TestDesktopNodeChainSOCKSSelectionRejectsForeignCapture": [
            "generic-family",
            "source",
            "config",
            "member",
            "server-key",
            "imported-family",
            "foreign-host",
            "replacement-policy"
        ],
        "TestDesktopNodeChainSOCKSSelectionRejectsServerAndIncompletePaths": []
    },
    "typed-platform-parent": {
        "TestDesktopNodeChainSOCKSParentProtectionAndOriginalRetirement": [
            "wg",
            "awg2-fast",
            "awg2-strong"
        ],
        "TestDesktopNodeChainSOCKSParentRejectsMixedOrReplacedPolicy": [
            "ordinary-chain",
            "ordinary-node",
            "imported",
            "prefix",
            "attempt-policy",
            "attempt-launch",
            "source-family"
        ],
        "TestDesktopNodeChainSOCKSProcessArgumentsRemainTyped": [
            "ordinary",
            "prefix",
            "imported-source",
            "credential",
            "duplicate-source",
            "foreign-directory",
            "invalid-mtu"
        ],
        "TestDesktopNodeChainSOCKSLinuxParentSourcePolicyAndArguments": [
            "wg",
            "awg2-fast",
            "awg2-strong"
        ],
        "TestDesktopNodeChainSOCKSLinuxTransactionRefusesForeignAuthority": [
            "ordinary",
            "imported",
            "prefix",
            "missing-source",
            "generic-source",
            "wrong-control",
            "wrong-session",
            "wrong-mode",
            "reconstructed-source"
        ],
        "TestDesktopNodeChainSOCKSLinuxMTURetainsExactPolicyAndPlatform": [
            "policy",
            "ordinary",
            "capture",
            "platform",
            "launch",
            "native",
            "session"
        ]
    },
    "typed-persistence": {
        "TestDesktopNodeChainSOCKSSavedProfileRoundTrip": [
            "wg",
            "awg2-fast",
            "awg2-strong"
        ],
        "TestDesktopNodeChainSOCKSSavedProfileRejectsSubstitution": [
            "credential",
            "endpoint",
            "public-identity",
            "paired-key",
            "node-identity",
            "source-digest",
            "middle-position",
            "server",
            "wrong-final",
            "layer"
        ],
        "TestDesktopNodeChainSOCKSLastSchemaAndCompleteInventory": [
            "wg",
            "awg2-fast",
            "awg2-strong"
        ],
        "TestDesktopNodeChainSOCKSLastRejectsGenericOrStaleSource": [
            "schema1",
            "schema2",
            "server",
            "proof-id",
            "missing-source",
            "source-kind",
            "wrong-final",
            "credential",
            "paired-source",
            "root"
        ],
        "TestDesktopNodeChainSOCKSStartupUsesOriginalTypedDriver": [
            "none",
            "credential",
            "source-away-back",
            "foreign-owner"
        ],
        "TestDesktopOrderedStartupSourceInventoryKeepsSchemaOneAndTwo": [
            "paired",
            "imported-ss"
        ]
    },
    "typed-ready": {
        "TestDesktopNodeChainSOCKSReadyUsesOriginalPolicy": [
            "linux",
            "windows",
            "darwin"
        ],
        "TestDesktopNodeChainSOCKSReadyRejectsForeignObservation": [
            "kind",
            "schema",
            "source",
            "transfer",
            "dns",
            "engine",
            "network",
            "session",
            "original-source",
            "config",
            "generation",
            "reader",
            "interface",
            "index",
            "low-mtu",
            "high-mtu",
            "time",
            "unknown",
            "whitespace",
            "null",
            "nil-policy"
        ]
    },
    "preserved-launch": {
        "TestDesktopNodeChainLaunchSealsFullSourceAndPlatform": [
            "windows/3",
            "linux/3",
            "darwin/3",
            "windows/4",
            "linux/4",
            "darwin/4",
            "windows/8",
            "linux/8",
            "darwin/8"
        ],
        "TestDesktopNodeChainLaunchRejectsCrossFamilyAndSourceSubstitution": [
            "config",
            "session",
            "middle",
            "source",
            "profile",
            "imported",
            "truncated",
            "platform"
        ],
        "TestDesktopNodeChainReadyPinsProofGenerationAndActualReader": [
            "engine",
            "network",
            "source",
            "config",
            "session",
            "dns",
            "transfer",
            "generation",
            "generation-jump",
            "reader",
            "index",
            "mtu",
            "old-proof",
            "future",
            "stale",
            "before-start",
            "fresh-after-replacement",
            "initial-active",
            "failure"
        ],
        "TestDesktopNodeChainReadyRequiresCanonicalPrivateHeartbeat": [],
        "TestDesktopNodeChainProtectionAndCommandKeepExactFamily": [],
        "TestDesktopNodeChainWorkspaceRetainsFullBoundAndJoinedFiles": [],
        "TestDesktopNodeChainDarwinReadyAllowsOnlyAdvancedUTUNReader": [
            "same-reader",
            "same-generation",
            "wrong-generation",
            "live-name",
            "non-utun",
            "empty-suffix",
            "invalid-suffix",
            "transfer",
            "identity",
            "dns",
            "fresh"
        ]
    },
    "preserved-measurement": {
        "TestDesktopNodeChainMeasurementRowsRequireEveryIndependentPrefix": [
            "missing",
            "reorder",
            "role",
            "undrained",
            "failed",
            "bytes",
            "derived-speed",
            "nan",
            "public-benchmark",
            "response",
            "stage",
            "samples",
            "distribution",
            "jitter",
            "missing#01",
            "reorder#01",
            "role#01",
            "undrained#01",
            "failed#01",
            "bytes#01",
            "derived-speed#01",
            "nan#01",
            "public-benchmark#01",
            "response#01",
            "stage#01",
            "samples#01",
            "distribution#01",
            "jitter#01"
        ],
        "TestDesktopNodeChainMeasurementExchangeJoinsExactMailbox": [
            "success",
            "cancel-drain"
        ],
        "TestDesktopNodeChainMeasurementHoldSurvivesPendingDrainUntilRetirement": [],
        "TestDesktopNodeChainMeasurementCancelCleanupHonorsCaller": []
    },
    "preserved-mtu": {
        "TestMTUNodeChainSnapshotRetainsEveryOriginalMember": [
            "2",
            "3",
            "4",
            "8",
            "2/0",
            "2/1",
            "3/0",
            "3/1",
            "3/2",
            "4/0",
            "4/1",
            "4/2",
            "4/3",
            "8/0",
            "8/1",
            "8/2",
            "8/3",
            "8/4",
            "8/5",
            "8/6",
            "8/7"
        ],
        "TestMTUNodeChainSnapshotRejectsRetainedOwnerReplacement": [
            "runtime",
            "launch",
            "command",
            "chain",
            "native",
            "policy",
            "capture",
            "sources",
            "network",
            "capture-network",
            "source",
            "config",
            "session",
            "platform",
            "graph-order",
            "selected",
            "missing-windows",
            "foreign-windows",
            "missing-ordered-snapshot"
        ],
        "TestMTUNodeChainPlatformSnapshotKeepsSeparateRegistryAndRefusesFallback": []
    },
    "macos-transfer": {
        "TestNodeChainSOCKSTransferCanonicalCaptureAndManifest": [],
        "TestNodeChainSOCKSTransferBindsEveryOriginalSelectionField": [
            "Session",
            "Source",
            "Config",
            "CallerUID",
            "WorkspaceDevice",
            "WorkspaceInode",
            "EngineSHA256",
            "ControllerSHA256",
            "CatalogSHA256",
            "InputsSHA256",
            "Family"
        ],
        "TestNodeChainSOCKSWireContractAndCrossFamilyRefusal": [
            "legacy-schema",
            "missing-family",
            "empty-family",
            "null-family",
            "unknown-family",
            "case-alias",
            "duplicate-family",
            "/ordered-node-chain-v1",
            "/node-candidate-prefix-v1",
            "/ordered-node-chain-socks-v1",
            "ordered-node-chain-v1/",
            "ordered-node-chain-v1/node-candidate-prefix-v1",
            "ordered-node-chain-v1/ordered-node-chain-socks-v1",
            "node-candidate-prefix-v1/",
            "node-candidate-prefix-v1/ordered-node-chain-v1",
            "node-candidate-prefix-v1/ordered-node-chain-socks-v1",
            "ordered-node-chain-socks-v1/",
            "ordered-node-chain-socks-v1/ordered-node-chain-v1",
            "ordered-node-chain-socks-v1/node-candidate-prefix-v1"
        ],
        "TestNodeChainSOCKSProtocolRequiresJoinedOriginalCleanup": [
            "joined",
            "retained-failure"
        ]
    },
    "macos-receipt": {
        "TestDesktopMacOSSOCKSBaselineKeepsExactFamily": [
            "ordered-node-chain-v1",
            "ordered-node-chain-socks-v1",
            "ordered-node-chain-v1/active",
            "ordered-node-chain-v1/held",
            "ordered-node-chain-v1/retired",
            "ordered-node-chain-socks-v1/active",
            "ordered-node-chain-socks-v1/held",
            "ordered-node-chain-socks-v1/retired"
        ]
    }
}
SOURCE_PATHS = (
    "cmd/client/desktop_node_chain_policy_dispatch.go",
    "cmd/client/multihop_node_chain_socks_selection_test.go",
    "cmd/client/desktop_node_chain_socks_parent_test.go",
    "cmd/client/desktop_node_chain_socks_parent_linux_test.go",
    "cmd/client/desktop_node_chain_socks_persistence_test.go",
    "internal/mobilemultihop/desktop_node_chain_socks_ready.go",
    "internal/mobilemultihop/desktop_node_chain_socks_ready_test.go",
    "internal/macosprocess/node_chain_socks_transfer.go",
    "internal/macosprocess/node_chain_socks_transfer_test.go",
    "cmd/client/desktop_node_chain_socks_darwin_baseline_test.go",
)
MTU_CONTRACT = {
    "baseline_selector": "^TestDesktopExternalLatency(SelectedPathPreservesProfilesAndExactIdentity|CompletedMTUResumeDoesNotContend)$",
    "required_tests": [
        "TestDesktopExternalLatencySelectedPathPreservesProfilesAndExactIdentity/live-three-response/manual-priority",
        "TestDesktopExternalLatencySelectedPathPreservesProfilesAndExactIdentity/live-three-response/idle-mtu-resumption/probe-cancelled",
        "TestDesktopExternalLatencySelectedPathPreservesProfilesAndExactIdentity/live-three-response/idle-mtu-resumption/retired",
        "TestDesktopExternalLatencySelectedPathPreservesProfilesAndExactIdentity/live-three-response/idle-mtu-resumption/replaced",
        "TestDesktopExternalLatencySelectedPathPreservesProfilesAndExactIdentity/live-three-response/idle-mtu-resumption/already-started",
        "TestDesktopExternalLatencySelectedPathPreservesProfilesAndExactIdentity/live-three-response/idle-mtu-resumption",
        "TestDesktopExternalLatencySelectedPathPreservesProfilesAndExactIdentity/live-three-response/valid",
        "TestDesktopExternalLatencySelectedPathPreservesProfilesAndExactIdentity/live-three-response/expiry",
        "TestDesktopExternalLatencySelectedPathPreservesProfilesAndExactIdentity/live-three-response/source",
        "TestDesktopExternalLatencySelectedPathPreservesProfilesAndExactIdentity/live-three-response/mtu-owner",
        "TestDesktopExternalLatencySelectedPathPreservesProfilesAndExactIdentity/live-three-response/network",
        "TestDesktopExternalLatencySelectedPathPreservesProfilesAndExactIdentity/live-three-response/cancel",
        "TestDesktopExternalLatencySelectedPathPreservesProfilesAndExactIdentity/live-three-response/partial",
        "TestDesktopExternalLatencySelectedPathPreservesProfilesAndExactIdentity/live-three-response/busy-mtu",
        "TestDesktopExternalLatencySelectedPathPreservesProfilesAndExactIdentity/live-three-response/manual50",
        "TestDesktopExternalLatencySelectedPathPreservesProfilesAndExactIdentity/live-three-response/partial#01",
        "TestDesktopExternalLatencySelectedPathPreservesProfilesAndExactIdentity/live-three-response/idle",
        "TestDesktopExternalLatencySelectedPathPreservesProfilesAndExactIdentity/live-three-response/transfer",
        "TestDesktopExternalLatencySelectedPathPreservesProfilesAndExactIdentity/live-three-response/wrong-node",
        "TestDesktopExternalLatencySelectedPathPreservesProfilesAndExactIdentity/live-three-response/endpoint",
        "TestDesktopExternalLatencySelectedPathPreservesProfilesAndExactIdentity/live-three-response/nan",
        "TestDesktopExternalLatencySelectedPathPreservesProfilesAndExactIdentity/live-three-response/undrained",
        "TestDesktopExternalLatencySelectedPathPreservesProfilesAndExactIdentity/live-three-response/count",
        "TestDesktopExternalLatencySelectedPathPreservesProfilesAndExactIdentity/live-three-response/fifty",
        "TestDesktopExternalLatencySelectedPathPreservesProfilesAndExactIdentity/live-three-response",
        "TestDesktopExternalLatencySelectedPathPreservesProfilesAndExactIdentity",
        "TestDesktopExternalLatencyCompletedMTUResumeDoesNotContend/completed-owner",
        "TestDesktopExternalLatencyCompletedMTUResumeDoesNotContend/replacement-owner",
        "TestDesktopExternalLatencyCompletedMTUResumeDoesNotContend"
    ],
    "control": {
        "source": "cmd/client/desktop_external_mtu.go",
        "before": "\t// A repeated resume for this exact already-scheduled owner is a no-op.\n\t// Do not queue a worker which can briefly take the MTU start lock from a\n\t// live response merely to discover the same completed Auto flag later.\n\tif retained := desktopMeasurementMTUSession(launch); retained != nil {\n\t\tretained.mu.Lock()\n\t\tautomatic := retained.automatic\n\t\tretained.mu.Unlock()\n\t\tif automatic && desktopMeasurementMTUSession(launch) == retained {\n\t\t\treturn\n\t\t}\n\t}\n",
        "after": "",
        "selector": "^TestDesktopExternalLatencyCompletedMTUResumeDoesNotContend$/^completed-owner$",
        "required_tests": [
            "TestDesktopExternalLatencyCompletedMTUResumeDoesNotContend/completed-owner",
            "TestDesktopExternalLatencyCompletedMTUResumeDoesNotContend"
        ],
        "required_failure_witness": "completed Auto resume entered catalog or queued MTU contention",
        "expected": "nonzero normal test exit; both exact records fail; precise witness only in original leaf; no build/race/panic/timeout rejection substitute"
    }
}
MUTATION_PATHS = {
    "completed-auto-contention": "cmd/client/desktop_external_mtu.go",
    "foreign-source-pointer": "cmd/client/desktop_node_chain_policy_dispatch.go",
    "generic-ready-kind": "internal/mobilemultihop/desktop_node_chain_socks_ready.go",
    "omitted-catalog-retirement": CAPTURE.SOURCE,
}


def records(groups: dict[str, list[str]]) -> frozenset[str]:
    return frozenset(groups) | frozenset(root + "/" + leaf for root, leaves in groups.items() for leaf in leaves)


def positive(name: str) -> Case:
    return Case(name, "^(" + "|".join(GROUPS[name]) + ")$", records(GROUPS[name]), 120, 600)


def cases(suite: str = SUITE) -> tuple[Case, ...]:
    if suite != SUITE:
        raise ValueError("unknown desktop parent suite")
    source = "TestDesktopNodeChainSOCKSSelectionRejectsForeignCapture"
    ready = "TestDesktopNodeChainSOCKSReadyRejectsForeignObservation"
    return (
        *(positive(name) for name in ("typed-selection", "typed-platform-parent", "typed-persistence", "typed-ready")),
        *CAPTURE.cases()[:2],
        *(positive(name) for name in ("preserved-launch", "preserved-measurement", "preserved-mtu", "macos-transfer", "macos-receipt")),
        Case("foreign-source-pointer", "^" + source + "$/^replacement-policy$",
             frozenset((source, source + "/replacement-policy")), 120, 600, "foreign-source-pointer",
             "equal JSON replaced original typed source object", frozenset((source + "/replacement-policy",))),
        Case("generic-ready-kind", "^" + ready + "$/^kind$",
             frozenset((ready, ready + "/kind")), 120, 600, "generic-ready-kind",
             "typed Ready admitted a foreign or noncanonical observation", frozenset((ready + "/kind",))),
        Case("completed-auto-resume", MTU_CONTRACT["baseline_selector"], frozenset(MTU_CONTRACT["required_tests"]), 120, 600),
        Case("completed-auto-contention", MTU_CONTRACT["control"]["selector"],
             frozenset(MTU_CONTRACT["control"]["required_tests"]), 120, 600, "completed-auto-contention",
             MTU_CONTRACT["control"]["required_failure_witness"],
             frozenset((MTU_CONTRACT["control"]["required_tests"][0],))),
        CAPTURE.cases()[2],
    )


def package_for(case: Case) -> str:
    if case.name in ("typed-ready", "generic-ready-kind"):
        return "internal/mobilemultihop"
    if case.name == "macos-transfer":
        return "internal/macosprocess"
    return "cmd/client"


def verdict(raw: bytes, case: Case, code: int, timed_out: bool = False, joined: bool = True) -> dict:
    CORE.PACKAGE = "router-vpn/" + package_for(case)
    return CORE.verdict(raw, case, code, timed_out, joined)


def mutation_source(case: Case, source: str) -> str:
    if case.mutation == "omitted-catalog-retirement":
        return CAPTURE.mutation_source(case, source)
    edits = {
        "completed-auto-contention": (MTU_CONTRACT["control"]["before"], MTU_CONTRACT["control"]["after"]),
        "foreign-source-pointer": ("return err == nil && original == c.socks.source",
                                   "return err == nil && original != nil"),
        "generic-ready-kind": ('r.Schema != 1 || r.Kind != "routervpn-node-chain-socks-ready-v1" ||',
                               "r.Schema != 1 ||"),
    }
    if case.mutation not in edits:
        raise ValueError("unknown desktop parent control")
    old, new = edits[case.mutation]
    if source.count(old) != 1:
        raise ValueError("desktop parent control lost its one exact original guard")
    return source.replace(old, new, 1)


def command_for(go: str, case: Case, overlay: Path | None = None) -> list[str]:
    command = CAPTURE.command_for(go, case, overlay)
    command[-1] = "./" + package_for(case)
    return command


def formatting_report(goroot: Path, source: Path, output: Path, selection: dict, before: dict, env: dict) -> dict:
    # -d produces a reviewable patch only; formatting differences do not skip compilation.
    paths = sorted(change["path"] for change in selection["changes"] if change["path"].endswith(".go"))
    if not paths or any(path not in before for path in paths):
        raise ValueError("formatting report requires captured changed Go files")
    command = [str(goroot / "bin" / "gofmt"), "-d", *[str(source / path) for path in paths]]
    log = output / "gofmt-readonly.patch"
    code, timed_out, joined = CORE.execute(command, source, env, log, 60)
    raw = log.read_bytes()
    return dict(command=command, paths=paths, exit=code, timed_out=timed_out, process_group_joined=joined,
                log=log.name, log_sha256=hashlib.sha256(raw).hexdigest(), has_diff=bool(raw),
                candidate_mutated=False, mode="read-only-diff")


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
        raise ValueError("candidate lost one original regular desktop parent file")
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
        "trusted_capture_sha256": hashlib.sha256(CAPTURE_PATH.read_bytes()).hexdigest(),
        "trusted_executor_sha256": hashlib.sha256(CORE_PATH.read_bytes()).hexdigest(),
        "go": go, "go_version": version, "go_environment": go_environment,
        "resource_limits": {"parallel_packages": 2, "GOMAXPROCS": 2, "GOGC": 100, "GOMEMLIMIT": "2GiB"},
        "status": "running", "attempts": [],
        "scope": "Actual typed parent source, policy, modeled process/kernel ownership, persistence and original lifecycle fixtures; no installed native, Darwin kernel, public admission or UI acceptance.",
    }

    def save() -> None:
        (output / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")

    save()
    try:
        formatting = formatting_report(goroot, source, output, selection, before, env)
        manifest["formatting"] = formatting
        save()
        if formatting["timed_out"] or not formatting["process_group_joined"]:
            raise RuntimeError("read-only formatter did not join within its original bound")
        if CORE.snapshot(source) != before or CORE.git(source, "status", "--porcelain", "--untracked-files=all"):
            raise RuntimeError("candidate source changed during read-only formatting")
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
            record = verdict(raw, case, code, timed_out, joined)
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
        if formatting["exit"] != 0:
            raise RuntimeError("read-only formatter failed; actual compilation receipts remain recorded")
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
