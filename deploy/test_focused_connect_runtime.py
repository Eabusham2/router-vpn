#!/usr/bin/env python3
"""Compose ordered CONNECT runtime checks with the original shared proof gate."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
SUITE = "connect-runtime"
BASE_PATH = Path(__file__).resolve().with_name("test_focused_socks_runtime.py")
_spec = importlib.util.spec_from_file_location("routervpn_connect_original_runtime", BASE_PATH)
BASE = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = BASE
_spec.loader.exec_module(BASE)
ORIGINAL_CASES = BASE.cases()
ORIGINAL_SOURCE_PATHS = BASE.SOURCE_PATHS
ORIGINAL_MUTATION_PATHS = dict(BASE.MUTATION_PATHS)
ORIGINAL_MUTATION_SOURCE = BASE.mutation_source
INVENTORY = json.loads(r'''{
  "selector": "^TestNodeChainCONNECTRuntime",
  "required": [
    "TestNodeChainCONNECTRuntimeUsesOriginalProofLifecycle",
    "TestNodeChainCONNECTRuntimeUsesOriginalProofLifecycle/wg/http-connect",
    "TestNodeChainCONNECTRuntimeUsesOriginalProofLifecycle/wg/https-connect",
    "TestNodeChainCONNECTRuntimeUsesOriginalProofLifecycle/awg2-fast/http-connect",
    "TestNodeChainCONNECTRuntimeUsesOriginalProofLifecycle/awg2-fast/https-connect",
    "TestNodeChainCONNECTRuntimeUsesOriginalProofLifecycle/awg2-strong/http-connect",
    "TestNodeChainCONNECTRuntimeUsesOriginalProofLifecycle/awg2-strong/https-connect",
    "TestNodeChainCONNECTRuntimeRequiresExactNativeMiddle",
    "TestNodeChainCONNECTRuntimeRequiresExactNativeMiddle/missing-interface",
    "TestNodeChainCONNECTRuntimeRequiresExactNativeMiddle/source-object",
    "TestNodeChainCONNECTRuntimeRequiresExactNativeMiddle/config",
    "TestNodeChainCONNECTRuntimeRequiresExactNativeMiddle/metadata",
    "TestNodeChainCONNECTRuntimeRequiresExactNativeMiddle/manager",
    "TestNodeChainCONNECTRuntimeRequiresExactNativeMiddle/middle",
    "TestNodeChainCONNECTRuntimeRequiresExactNativeMiddle/lower",
    "TestNodeChainCONNECTRuntimeRequiresExactNativeMiddle/carrier",
    "TestNodeChainCONNECTRuntimeRequiresExactNativeMiddle/retired",
    "TestNodeChainCONNECTRuntimeRetiresChangedOwner",
    "TestNodeChainCONNECTRuntimeRetiresChangedOwner/manager",
    "TestNodeChainCONNECTRuntimeRetiresChangedOwner/middle",
    "TestNodeChainCONNECTRuntimeRetiresChangedOwner/lower",
    "TestNodeChainCONNECTRuntimeRetiresChangedOwner/carrier",
    "TestNodeChainCONNECTRuntimeRetiresChangedOwner/retired",
    "TestNodeChainCONNECTRuntimeRetiresChangedOwner/engine",
    "TestNodeChainCONNECTRuntimeRetiresChangedOwner/session",
    "TestNodeChainCONNECTRuntimeRetiresChangedOwner/network",
    "TestNodeChainCONNECTRuntimeRetiresChangedOwner/source-hash",
    "TestNodeChainCONNECTRuntimeRetiresChangedOwner/config-hash",
    "TestNodeChainCONNECTRuntimeRetiresChangedOwner/selection",
    "TestNodeChainCONNECTRuntimePreservesProofRefusals",
    "TestNodeChainCONNECTRuntimePreservesProofRefusals/first-private",
    "TestNodeChainCONNECTRuntimePreservesProofRefusals/middle-route",
    "TestNodeChainCONNECTRuntimePreservesProofRefusals/middle-public-ip",
    "TestNodeChainCONNECTRuntimePreservesProofRefusals/final-private",
    "TestNodeChainCONNECTRuntimePreservesProofRefusals/final-dns",
    "TestNodeChainCONNECTRuntimePreservesProofRefusals/middle-tls",
    "TestNodeChainCONNECTRuntimePreservesProofRefusals/changed-source",
    "TestNodeChainCONNECTRuntimeJoinsOriginalCancellation",
    "TestNodeChainCONNECTRuntimeJoinsOriginalCancellation/middle-observer",
    "TestNodeChainCONNECTRuntimeJoinsOriginalCancellation/middle-dial",
    "TestNodeChainCONNECTRuntimeJoinsOriginalCancellation/returned-close",
    "TestNodeChainCONNECTRuntimeMeasurementKeepsPublicScopeAndDrain",
    "TestNodeChainCONNECTRuntimeKeepsGenericAdmissionClosed",
    "TestNodeChainCONNECTRuntimeRejectsPrivateCaptureSubstitution",
    "TestNodeChainCONNECTRuntimeRejectsPrivateCaptureSubstitution/equal-source-object",
    "TestNodeChainCONNECTRuntimeRejectsPrivateCaptureSubstitution/imported-owner",
    "TestNodeChainCONNECTRuntimeRejectsPrivateCaptureSubstitution/socks-owner",
    "TestNodeChainCONNECTRuntimeRejectsPrivateCaptureSubstitution/config",
    "TestNodeChainCONNECTRuntimeRejectsPrivateCaptureSubstitution/dns",
    "TestNodeChainCONNECTRuntimeRejectsPrivateCaptureSubstitution/projection",
    "TestNodeChainCONNECTRuntimeRechecksSourceAfterNativeObserver",
    "TestNodeChainCONNECTRuntimeMeasurementRejectsEqualByteForeignSource"
  ],
  "controls": [
    {
      "name": "omitted-initial-connect-observer",
      "path": "internal/mobilemultihop/node_chain_runtime.go",
      "before": "\tif err := c.observeCONNECTMiddleContext(ctx, engine); err != nil {\n\t\treturn err\n\t}\n\tif err := c.observeSOCKSMiddleContext(ctx, engine); err != nil {\n\t\treturn err\n\t}\n\tif err := externalObservationLock(ctx, &c.runtime.mu); err != nil {\n",
      "after": "\tif err := c.observeSOCKSMiddleContext(ctx, engine); err != nil {\n\t\treturn err\n\t}\n\tif err := externalObservationLock(ctx, &c.runtime.mu); err != nil {\n",
      "selector": "^TestNodeChainCONNECTRuntimeRequiresExactNativeMiddle$",
      "failures": [
        "TestNodeChainCONNECTRuntimeRequiresExactNativeMiddle",
        "TestNodeChainCONNECTRuntimeRequiresExactNativeMiddle/missing-interface",
        "TestNodeChainCONNECTRuntimeRequiresExactNativeMiddle/source-object",
        "TestNodeChainCONNECTRuntimeRequiresExactNativeMiddle/config",
        "TestNodeChainCONNECTRuntimeRequiresExactNativeMiddle/metadata",
        "TestNodeChainCONNECTRuntimeRequiresExactNativeMiddle/manager",
        "TestNodeChainCONNECTRuntimeRequiresExactNativeMiddle/middle",
        "TestNodeChainCONNECTRuntimeRequiresExactNativeMiddle/lower",
        "TestNodeChainCONNECTRuntimeRequiresExactNativeMiddle/carrier",
        "TestNodeChainCONNECTRuntimeRequiresExactNativeMiddle/retired"
      ],
      "witness": "missing original CONNECT owner reached native selection or proof"
    },
    {
      "name": "omitted-current-connect-observer",
      "path": "internal/mobilemultihop/node_chain_runtime.go",
      "before": "\tif err := c.observeCONNECTMiddleContext(ctx, engine); err != nil {\n\t\treturn err\n\t}\n\tif err := c.observeSOCKSMiddleContext(ctx, engine); err != nil {\n\t\treturn err\n\t}\n\tif selected {\n",
      "after": "\tif err := c.observeSOCKSMiddleContext(ctx, engine); err != nil {\n\t\treturn err\n\t}\n\tif selected {\n",
      "selector": "^TestNodeChainCONNECTRuntimeRetiresChangedOwner$/^(manager|middle|lower|carrier|retired)$",
      "failures": [
        "TestNodeChainCONNECTRuntimeRetiresChangedOwner",
        "TestNodeChainCONNECTRuntimeRetiresChangedOwner/manager",
        "TestNodeChainCONNECTRuntimeRetiresChangedOwner/middle",
        "TestNodeChainCONNECTRuntimeRetiresChangedOwner/lower",
        "TestNodeChainCONNECTRuntimeRetiresChangedOwner/carrier",
        "TestNodeChainCONNECTRuntimeRetiresChangedOwner/retired"
      ],
      "witness": "changed original CONNECT owner remained healthy"
    },
    {
      "name": "discarded-original-connect-join",
      "path": "internal/mobilemultihop/node_chain_connect_runtime.go",
      "before": "\treturn r.chain.CloseContext(ctx)\n",
      "after": "\treturn nil\n",
      "selector": "^TestNodeChainCONNECTRuntimeJoinsOriginalCancellation$/^middle-observer$",
      "failures": [
        "TestNodeChainCONNECTRuntimeJoinsOriginalCancellation",
        "TestNodeChainCONNECTRuntimeJoinsOriginalCancellation/middle-observer"
      ],
      "witness": "shared close abandoned original CONNECT work"
    },
    {
      "name": "equal-byte-foreign-measurement-source",
      "path": "internal/mobilemultihop/node_chain_connect_runtime.go",
      "before": "active.source != o.source ||\n\t\tactive.chain.connectSource != o.source || ",
      "after": "",
      "selector": "^TestNodeChainCONNECTRuntimeMeasurementRejectsEqualByteForeignSource$",
      "failures": [
        "TestNodeChainCONNECTRuntimeMeasurementRejectsEqualByteForeignSource"
      ],
      "witness": "equal-byte foreign CONNECT source acquired original measurement"
    }
  ],
  "files": [
    "internal/mobilemultihop/desktop_egress.go",
    "internal/mobilemultihop/node_chain.go",
    "internal/mobilemultihop/node_chain_connect_physical.go",
    "internal/mobilemultihop/node_chain_connect_runtime.go",
    "internal/mobilemultihop/node_chain_connect_runtime_test.go",
    "internal/mobilemultihop/node_chain_connect_source.go",
    "internal/mobilemultihop/node_chain_connect_source_test.go",
    "internal/mobilemultihop/node_chain_graph.go",
    "internal/mobilemultihop/node_chain_imported_connect.go",
    "internal/mobilemultihop/node_chain_runtime.go",
    "internal/mobilemultihop/node_chain_socks_runtime.go"
  ]
}''')

def cases(suite=SUITE):
    if suite != SUITE:
        raise ValueError("Only the fixed CONNECT runtime suite is accepted")
    additional = [BASE.Case("ordered-connect-runtime", INVENTORY["selector"],
                           frozenset(INVENTORY["required"]), 120, 600)]
    for control in INVENTORY["controls"]:
        required = frozenset(control["failures"])
        witnesses = frozenset(name for name in required if "/" in name) or required
        additional.append(BASE.Case(control["name"], control["selector"], required, 120, 600,
                                    control["name"], control["witness"], witnesses))
    return (*ORIGINAL_CASES, *additional)

def mutation_source(case, source):
    selected = [c for c in INVENTORY["controls"] if c["name"] == case.mutation]
    if not selected:
        return ORIGINAL_MUTATION_SOURCE(case, source)
    control = selected[0]
    if source.count(control["before"]) != 1 or control["before"] == control["after"]:
        raise ValueError("CONNECT control lost its one exact original guard")
    return source.replace(control["before"], control["after"], 1)

BASE.SUITE = SUITE
BASE.cases = cases
BASE.SOURCE_PATHS = tuple(dict.fromkeys((*ORIGINAL_SOURCE_PATHS, *INVENTORY["files"])))
BASE.MUTATION_PATHS = {**ORIGINAL_MUTATION_PATHS,
                       **{c["name"]: c["path"] for c in INVENTORY["controls"]}}
BASE.mutation_source = mutation_source

def validate(args):
    cases(args.suite)
    output = Path(args.output).resolve()
    manifest_path = output / "manifest.json"
    if manifest_path.exists() or manifest_path.is_symlink():
        raise ValueError("CONNECT validation requires a fresh original manifest")
    original_execute = BASE.CORE.execute
    formatting = None
    def execute(command, source, environment, log, outer_seconds):
        nonlocal formatting
        if formatting is None:
            # The original driver has captured the exact clean source, compiler
            # and environment before it reaches its first immutable test case.
            before = json.loads((output / "source-before.json").read_text())
            format_command = [str(Path(command[0]).with_name("gofmt")), "-d",
                              *(str(source / p) for p in INVENTORY["files"])]
            format_log = output / "gofmt.patch"
            code, timed_out, joined = original_execute(
                format_command, source, environment, format_log, 60)
            raw = format_log.read_bytes()
            formatting = {"command": format_command, "exit": code, "timed_out": timed_out,
                          "process_group_joined": joined, "outer_seconds": 60,
                          "log": format_log.name, "log_sha256": hashlib.sha256(raw).hexdigest(),
                          "diff_present": bool(raw)}
            if BASE.CORE.snapshot(source) != before:
                raise RuntimeError("CONNECT formatter changed captured original source")
            if (code, timed_out, joined) != (0, False, True) or raw:
                raise RuntimeError("original read-only formatter requires a clean joined result")
        return original_execute(command, source, environment, log, outer_seconds)
    BASE.CORE.execute = execute
    try:
        BASE.validate(args)
    finally:
        BASE.CORE.execute = original_execute
        if manifest_path.exists():
            value = json.loads(manifest_path.read_text())
            if value.get("suite") != SUITE or value.get("requested_source_sha") != args.source_sha or value.get("actual_source_sha") != args.source_sha:
                raise ValueError("CONNECT composition cannot adopt a foreign original manifest")
            value["formatting"] = formatting
            value["composition"] = {
                "driver_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                "original_driver_sha256": hashlib.sha256(BASE_PATH.read_bytes()).hexdigest(),
                "original_attempts": 6, "original_records": 80, "new_runtime_records": 52,
                "new_compiled_controls": 4, "encrypted_native_host_delivery": "unfinished"}
            value["scope"] = "Shared CONNECT proof lifecycle with original HTTP/TLS and explicit native owner doubles; no encrypted CONNECT, Box, TUN or UI acceptance."
            manifest_path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", choices=(SUITE,), required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--output", required=True)
    validate(parser.parse_args())

if __name__ == "__main__":
    main()
