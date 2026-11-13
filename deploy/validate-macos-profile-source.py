#!/usr/bin/env python3
"""Execute the original macOS profile fixture with exact source and verdicts.

Widgets, HTTP and scheduling retain the fixture's explicit boundaries. This
gate compiles the shipping Swift model and callbacks; it does not establish
native tunnels, physical visual acceptance, signing or complete app packaging.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import time

CORE_PATH = Path(__file__).resolve().with_name("test_focused_multihop_clocks.py")
_spec = importlib.util.spec_from_file_location("routervpn_macos_profile_executor", CORE_PATH)
if _spec is None or _spec.loader is None:
    raise RuntimeError("original focused process executor is missing")
CORE = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = CORE
_spec.loader.exec_module(CORE)

CONTROL_NAMES = (
    "manager-two-mode-capture",
    "settings-two-mode-capture",
    "manager-entry-capture",
    "main-entry-connect",
    "main-progress-owner",
    "main-startup-deadline",
    "unsupported-entry-load",
    "unsupported-load",
    "selection-generation",
    "request-order",
    "same-id-relink",
    "first-node-fallback",
    "post-response-manager-idle",
    "post-response-settings-idle",
    "ordered-drop-middle",
    "ordered-final-owner",
    "ordered-middle-source",
    "ordered-capability",
    "ordered-request-owner",
    "ordered-locked-source-preconditions",
    "ordered-final-draft",
    "ordered-final-snapshot",
    "ordered-final-apply",
    "ordered-final-widget",
    "ordered-final-layer",
    "ordered-imported-final",
    "ordered-imported-choice",
    "ordered-loaded-final",
    "setup-source-preconditions",
    "setup-generation",
    "setup-mode",
    "setup-live-source",
    "setup-response-source",
    "setup-response-order",
    "setup-load-inventory",
    "setup-response-inventory",
    "setup-stale-body",
    "ordered-socks-protocol",
    "ordered-socks-draft-mode",
    "ordered-socks-capability",
    "ordered-socks-final",
)
SCRIPT = "deploy/test_desktop_connection_profile_modes.py"
SOURCE_PATH = "client/macos/RouterVPNConnectionProfiles.swift"
OUTER_SECONDS = 1800


def verdict(raw: bytes, code: int, timed_out: bool, joined: bool) -> dict:
    text = raw.decode("utf-8", "strict")
    positives = re.findall(r"^Actual AppKit profiles, deferred catalogs and Settings Add/Load/Update callbacks: ([1-9][0-9]*) checks PASS$", text, re.MULTILINE)
    controls = re.findall(r"^PASS causal AppKit ([^\r\n]+)$", text, re.MULTILINE)
    terminals = re.findall(r"^AppKit capture, refresh ownership, relink and post-response idle negatives: ([0-9]+) rejected$", text, re.MULTILINE)
    accepted = (code == 0 and not timed_out and joined and len(positives) == 1
                and tuple(controls) == CONTROL_NAMES and terminals == [str(len(CONTROL_NAMES))])
    return {"accepted": accepted, "exit": code, "timed_out": timed_out,
            "process_group_joined": joined, "positive_check_counts": positives,
            "controls": controls, "terminal_counts": terminals}


def validate(args: argparse.Namespace) -> None:
    if platform.system() != "Darwin" or platform.machine() not in ("arm64", "x86_64"):
        raise ValueError("macOS profile validation requires an actual native macOS runner")
    if not re.fullmatch(r"[0-9a-f]{40}", args.source_sha):
        raise ValueError("source SHA must be an exact lowercase commit")
    source, output = Path(args.source).resolve(), Path(args.output).resolve()
    if output == source or source in output.parents:
        raise ValueError("validation output must be outside the original source")
    if output.exists() and any(output.iterdir()):
        raise ValueError("validation output must be fresh")
    if CORE.git(source, "rev-parse", "HEAD").decode().strip() != args.source_sha:
        raise ValueError("source checkout differs from the requested commit")
    if CORE.git(source, "status", "--porcelain", "--untracked-files=all"):
        raise ValueError("source checkout is not clean")
    before = CORE.snapshot(source)
    if any(path not in before or before[path]["mode"] != "100644" for path in (SCRIPT, SOURCE_PATH)):
        raise ValueError("original macOS fixture or shipping source is missing")
    swift = shutil.which("swiftc")
    if not swift:
        raise ValueError("the native Swift compiler is required")
    version = subprocess.check_output([swift, "--version"], text=True, timeout=30).strip()
    if "Apple Swift version " not in version or "-apple-macosx" not in version:
        raise ValueError("compiler did not report a native Apple Swift toolchain")
    output.mkdir(parents=True, exist_ok=True)
    snapshot = json.dumps(before, sort_keys=True, separators=(",", ":")).encode()
    (output / "source-before.json").write_bytes(snapshot + b"\n")
    manifest = {
        "schema": 1, "suite": "macos-profiles", "requested_source_sha": args.source_sha,
        "actual_source_sha": CORE.git(source, "rev-parse", "HEAD").decode().strip(),
        "tree_sha": CORE.git(source, "rev-parse", "HEAD^{tree}").decode().strip(),
        "source_file_count": len(before), "source_closure_sha256": hashlib.sha256(snapshot).hexdigest(),
        "validator_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "trusted_executor_sha256": hashlib.sha256(CORE_PATH.read_bytes()).hexdigest(),
        "swift": swift, "swift_version": version, "native_architecture": platform.machine(),
        "outer_seconds": OUTER_SECONDS, "required_controls": list(CONTROL_NAMES),
        "status": "running", "native_tunnel_accepted": False, "complete_app_build_accepted": False,
    }

    def save() -> None:
        (output / "manifest.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")

    save()
    try:
        command = [sys.executable, str(source / SCRIPT), "--platform", "macos"]
        log = output / "macos-profiles.log"
        started = time.monotonic()
        code, timed_out, joined = CORE.execute(command, source, dict(os.environ, PYTHONDONTWRITEBYTECODE="1"), log, OUTER_SECONDS)
        raw = log.read_bytes()
        manifest.update(verdict(raw, code, timed_out, joined))
        manifest.update(command=command, log=log.name, log_sha256=hashlib.sha256(raw).hexdigest(),
                        elapsed_seconds=round(time.monotonic() - started, 3))
        if not manifest["accepted"]:
            raise RuntimeError("original Swift execution did not produce every required verdict")
        if CORE.snapshot(source) != before or CORE.git(source, "status", "--porcelain", "--untracked-files=all"):
            raise RuntimeError("original source changed during Swift validation")
        manifest["status"] = "passed"
        print(json.dumps(manifest, sort_keys=True), flush=True)
    except BaseException as error:
        manifest["status"] = "failed"
        manifest["error"] = str(error)
        raise
    finally:
        save()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--output", required=True)
    validate(parser.parse_args())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
