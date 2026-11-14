#!/usr/bin/env python3
"""Installed Windows selected-prefix acceptance using actual owned native paths.

The controller, journal IPC/storage, Wintun packet owner, isolated physical
socket source, encrypted peers and candidate probes are real. The only native
scope change is a compile-time WFP AppID condition for the captured child, so
the disposable runner is not globally blocked. The original completed bundle
is independently verified; its test-scoped engine and resealed receipt are
recorded separately and are never described as an unmodified shipping image.
"""
from pathlib import Path
import argparse
import ctypes
import hashlib
import importlib.util
import json
import os
import platform
import re
import shutil
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "deploy" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SCOPE = load("windows_prefix_scope", "windows_candidate_prefix_overlay.py")
CONTROLLER = load("windows_prefix_controller", "test_windows_controller_privilege.py")
NODE = load("windows_prefix_native_source", "test_desktop_node_physical.py")
BUILD = load("windows_prefix_complete_bundle", "build-native-runtime.py")
SOCKS_PARENT = load("windows_retained_socks_parent", "test_desktop_socks_parent.py")
ROOT_TEST = "TestWindowsInstalledPrefixCandidates"
CASES = ("wg-save", "wg-cancel", "awg-fast-save", "awg-fast-cancel", "awg-strong-save", "awg-strong-cancel")
REQUIRED = (ROOT_TEST, *(ROOT_TEST + "/" + case for case in CASES))
PREFIX = "Native Windows selected-prefix acceptance: "
OWNED = ("deploy/test_desktop_socks_parent.py", "deploy/test_desktop_socks_parent_runner.py",
         "cmd/client/desktop_node_chain_socks_platform_test.go",
         "cmd/client/ordered_candidate_prefix_windows_native_test.go",
         "cmd/client/ordered_candidate_prefix_windows_sources_native_test.go",
         "deploy/test_windows_candidate_prefix.py", "deploy/test_windows_candidate_prefix_runner.py",
         "deploy/windows_candidate_prefix_overlay.py",
         "deploy/fixtures/windows-candidate-prefix/scope.go",
         "deploy/fixtures/windows-candidate-prefix/peer.go")


def sources(source):
    source, native = NODE.checked_sources(source)
    records = {"controller/" + name: digest for name, digest in CONTROLLER.sources().items()}
    records.update({"native/" + name: digest for name, digest in native.items()})
    for name in OWNED:
        path = ROOT / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("Installed prefix gate lost its original source: " + name)
        records["gate/" + name] = hashlib.sha256(path.read_bytes()).hexdigest()
    # No old harmless TUN or in-memory journal overlay is admitted by this
    # gate. The entire original template closure is sealed by NODE above.
    for name in ("mobile/desktop/node_candidate_prefix_command.go.tmpl",
                 "mobile/desktop/node_command_journal_windows.go.tmpl"):
        if "gate/" + name not in records:
            path = ROOT / name
            records["gate/" + name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return source, records


def require_verdicts(output):
    runs = re.findall(r"^\s*=== RUN\s+(\S+)\s*$", output, re.M)
    passes = re.findall(r"^\s*--- PASS:\s+(\S+)\s+\(", output, re.M)
    if "--- FAIL:" in output or "--- SKIP:" in output or "WARNING: DATA RACE" in output:
        raise ValueError("Installed prefix native gate failed, skipped or raced")
    if len(runs) != len(REQUIRED) or set(runs) != set(REQUIRED) or len(passes) != len(REQUIRED) or set(passes) != set(REQUIRED):
        raise ValueError("Installed prefix native gate omitted or duplicated an exact required verdict")
    for case in CASES:
        if output.count("verified installed Windows selected prefix: " + case + "\n") != 1:
            raise ValueError("Installed prefix native gate omitted its original lifecycle receipt: " + case)
    if not re.search(r"^PASS\s*$", output, re.M):
        raise ValueError("Installed prefix native gate omitted its successful process footer")


def merge_overlays(paths, target):
    replacements = {}
    for path in paths:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
        if set(value) != {"Replace"} or not isinstance(value["Replace"], dict):
            raise ValueError("Installed prefix overlay changed its compiler schema")
        for original, replacement in value["Replace"].items():
            if original in replacements:
                raise ValueError("Installed prefix overlays overlap original source")
            replacements[original] = replacement
    target.write_text(json.dumps({"Replace": replacements}, sort_keys=True), encoding="utf-8")
    return target


def execute(source, bundle, go="go", *, env=None):
    if platform.system() != "Windows" or not ctypes.windll.shell32.IsUserAnAdmin():
        raise ValueError("Installed prefix acceptance requires its actual elevated Windows host")
    source, before = sources(source)
    compiler, captured, architecture = CONTROLLER.NATIVE.selected_compiler(go, ROOT, dict(os.environ if env is None else env))
    captured["CGO_ENABLED"] = "1"
    target = "windows/" + architecture
    bundle = Path(bundle).resolve()
    original = BUILD.reuse(bundle, target, env=captured)
    original_manifest = hashlib.sha256((bundle / "NATIVE-RUNTIME.json").read_bytes()).hexdigest()
    race = ["-race"] if architecture == "amd64" else []
    run = CONTROLLER.NATIVE.run
    with tempfile.TemporaryDirectory(prefix="routervpn-windows-prefix-") as temporary:
        work = Path(temporary).resolve()
        installed = work / "installed"
        native = installed / "runtime/native"
        native.mkdir(parents=True)
        for name in original["files"]:
            shutil.copyfile(bundle / name, native / name)
        child = native / BUILD.binary_name(target)
        native_scope, native_records = SCOPE.overlay(source / "routervpn/mobiletor", child, work / "native-scope")
        app_scope, app_records = SCOPE.overlay(ROOT / "internal/mobiletor", child, work / "controller-scope")
        if native_records != app_records:
            raise ValueError("Installed prefix controller/native scope source diverged")
        loader = source / "cmd/sing-box/routervpn_native_library.go"
        loader_source = (ROOT / "mobile/desktop/native_library.go.tmpl").read_bytes()
        if loader.exists():
            if loader.is_symlink() or loader.read_bytes() != loader_source:
                raise ValueError("Installed prefix native library owner differs from its original source")
        else:
            # Cached bundles reconstruct prepared source before the final
            # executable-only loader is installed. Add the identical loader
            # privately; never mutate the prepared original source.
            added = work / "routervpn_native_library.go"
            added.write_bytes(loader_source)
            loader_overlay = work / "loader.json"
            loader_overlay.write_text(json.dumps({"Replace": {str(loader): str(added)}}), encoding="utf-8")
            native_scope = merge_overlays([native_scope, loader_overlay], work / "native-overlay.json")
        peer_overlay = SCOPE.peer_overlay(source / "protocol/routervpnamnezia", work / "peer-source")
        native_tags = (*BUILD.tags(target), SCOPE.TAG)
        ldflags = ("-checklinkname=0 -X github.com/sagernet/sing-box/constant.Version=" + BUILD.marker(original["policy_sha256"]) +
                   " -X main.routerVPNCronetSHA=" + original["files"]["libcronet.dll"]["sha256"] +
                   " -X main.routerVPNCronetBytes=" + str(original["files"]["libcronet.dll"]["size"]))
        peer, controller = work / "prefix-peer.test.exe", work / "prefix-controller.test.exe"
        commands = (
            ([compiler, "build", "-p=1", "-mod=readonly", "-trimpath", "-buildvcs=false", "-overlay=" + str(native_scope),
              "-tags=" + ",".join(native_tags), "-ldflags=" + ldflags, "-o", child, "./cmd/sing-box"], source),
            ([compiler, "test", "-c", "-p=1", "-mod=readonly", *race, "-overlay=" + str(peer_overlay),
              "-tags=" + ",".join((*NODE.TAGS, SCOPE.TAG)), "-ldflags=-checklinkname=0", "-o", peer, "./protocol/routervpnamnezia"], source),
            ([compiler, "test", "-c", "-p=1", "-mod=readonly", *race, "-overlay=" + str(app_scope),
              "-tags=" + SCOPE.TAG, "-o", controller, "./cmd/client"], ROOT))
        for command, cwd in commands:
            status, output = run(command, cwd=cwd, env=captured, timeout=600)
            if status:
                raise ValueError("Installed prefix actual source did not compile:\n" + output[-32768:])
        scoped = json.loads(json.dumps(original))
        child_bytes = child.read_bytes()
        payload = {"size": len(child_bytes), "sha256": hashlib.sha256(child_bytes).hexdigest()}
        scoped.update(payload)
        scoped["files"][child.name] = payload
        (native / "NATIVE-RUNTIME.json").write_text(json.dumps(scoped, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        # Retain every existing payload/architecture/marker check for the
        # explicitly labeled scoped image before the ordinary app verifier.
        BUILD.reuse(native, target, env=captured)
        identities = {name: hashlib.sha256(path.read_bytes()).hexdigest()
                      for name, path in (("controller", controller), ("peer", peer), ("scoped_engine", child))}
        # These retain the actual compiled platform parent, but their kernel
        # boundary is modeled. The following native prefix cases are unchanged
        # and do not constitute typed full-chain Connect acceptance.
        socks_parent_controls = SOCKS_PARENT.execute(controller, 'windows', run, ROOT, captured)
        child_env = dict(captured, ROUTERVPN_WINDOWS_PREFIX_ROOT=str(installed), ROUTERVPN_WINDOWS_PREFIX_PEER=str(peer))
        status, output = run([controller, "-test.v", "-test.count=1", "-test.timeout=700s", "-test.run=^" + ROOT_TEST + "$"],
                             cwd=ROOT, env=child_env, timeout=720)
        if status:
            raise ValueError("Installed prefix actual native lifecycle failed:\n" + output[-65536:])
        require_verdicts(output)
        if sources(source)[1] != before or BUILD.reuse(bundle, target, env=captured) != original:
            raise ValueError("Installed prefix original source/bundle changed during acceptance")
        if identities != {name: hashlib.sha256(path.read_bytes()).hexdigest()
                          for name, path in (("controller", controller), ("peer", peer), ("scoped_engine", child))}:
            raise ValueError("Installed prefix original executable changed during acceptance")
        print(output, end="" if output.endswith("\n") else "\n", flush=True)
        receipt = {"schema": 1, "native": True, "target": target, "cases": list(CASES),
                   "bundle_sha256": original_manifest, "source_sha256": original["policy_sha256"],
                   "unmodified_shipping_image": False, "test_scope": "captured-native-child-app-id",
                   "application_open": False, "dns_open": False, "samples_per_case": 50,
                   "original_final_unreachable": True, "native_down_before_review": True,
                   "sources": before, "scope_sources": native_records, "images": identities,
                   "typed_socks_parent_controls": socks_parent_controls}
        print(PREFIX + json.dumps(receipt, sort_keys=True), flush=True)
        return receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--go", default="go")
    args = parser.parse_args()
    execute(args.source, args.bundle, args.go)
