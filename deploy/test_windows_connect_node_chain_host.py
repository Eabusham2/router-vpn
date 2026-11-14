#!/usr/bin/env python3
"""Installed Windows typed CONNECT acceptance after original prefix6 and SOCKS8.

The full-path gate requires an encrypted packet prefix, authenticated TCP CONNECT, final SS UoT-v2,
selected DNS and authenticated exit proof, complete measurement and joined native
retirement. Original shipping sources/bundle and scoped image identities are
verified before and after. Prefix-only acceptance cannot replace this receipt.
"""
from pathlib import Path
from contextlib import contextmanager
from types import SimpleNamespace
import argparse
import ctypes
import hashlib
import importlib.util
import json
import os
import platform
import re
import shutil

ROOT = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "deploy" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SOCKS_GATE = load("windows_connect_original_socks", "test_windows_socks_node_chain_host.py")
PREFIX_GATE = SOCKS_GATE.PREFIX_GATE
SCOPE = load("windows_connect_scope", "windows_connect_node_chain_overlay.py")
CONTROLLER = load("windows_prefix_controller", "test_windows_controller_privilege.py")
NODE = load("windows_prefix_native_source", "test_desktop_node_physical.py")
BUILD = load("windows_prefix_complete_bundle", "build-native-runtime.py")
CONNECT_PARENT = load("windows_retained_connect_parent", "test_desktop_connect_parent.py")
COMMAND_OWNER = load("windows_socks_command_owner", "test_windows_node_max.py")
ROOT_TEST = "TestWindowsInstalledCONNECTNodeChain"
ORIGINAL_PREFIX_CASES = ("wg-save", "wg-cancel", "awg-fast-save", "awg-fast-cancel", "awg-strong-save", "awg-strong-cancel")
ORIGINAL_SOCKS_CASES = ("wg-connect", "awg-fast-connect", "awg-strong-connect", "wg-wrong-middle-key", "wg-wrong-middle-public", "wg-final-dns-failure", "wg-final-node-failure", "wg-middle-source")
CASES = ("http-wg-connect", "http-awg-fast-connect", "http-awg-strong-connect", "https-wg-connect", "https-awg-fast-connect", "https-awg-strong-connect", "https-wg-wrong-middle-key", "http-wg-wrong-middle-public", "https-wg-tls-name", "https-wg-tls-trust", "http-wg-final-dns-failure", "https-wg-final-node-failure", "https-wg-final-key", "https-wg-middle-source")
REQUIRED = (ROOT_TEST, *(ROOT_TEST + "/" + case for case in CASES))
PREFIX = "Native Windows typed CONNECT full-path acceptance: "
OWNED = (*SOCKS_GATE.OWNED,
         "cmd/client/desktop_node_chain_connect_windows_native_test.go",
         "cmd/client/desktop_node_chain_connect_windows_peer_native_test.go",
         "cmd/client/desktop_node_chain_connect_windows_controller_native_test.go",
         "deploy/test_windows_connect_node_chain_host.py",
         "deploy/test_windows_connect_node_chain_host_runner.py",
         "deploy/test_windows_connect_release_receipt.py",
         "deploy/windows_connect_node_chain_overlay.py",
         "deploy/fixtures/windows-connect-node-chain/peer.go",
         "mobile/desktop/node_chain_connect_peer_test.go.tmpl",
         "mobile/chain/connect_reference_test.go.tmpl",
         "deploy/test_desktop_connect_parent.py", "deploy/test_desktop_connect_parent_runner.py")


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
    for name, raw in SCOPE.peer_sources().items():
        records["peer-overlay/" + name] = hashlib.sha256(raw).hexdigest()
    return source, records


def require_verdicts(output):
    runs = re.findall(r"^\s*=== RUN\s+(\S+)\s*$", output, re.M)
    passes = re.findall(r"^\s*--- PASS:\s+(\S+)\s+\(", output, re.M)
    if any(value in output for value in ("--- FAIL:", "--- SKIP:", "WARNING: DATA RACE", "panic:", "fatal error:")):
        raise ValueError("Installed typed full-path native gate failed, skipped or raced")
    if len(runs) != len(REQUIRED) or set(runs) != set(REQUIRED) or len(passes) != len(REQUIRED) or set(passes) != set(REQUIRED):
        raise ValueError("Installed typed full-path native gate omitted or duplicated an exact required verdict")
    for case in CASES:
        if len(re.findall(r"(?m)^\s*(?:[A-Za-z0-9_./\\-]+\.go:[0-9]+: )?" + re.escape("verified installed Windows typed CONNECT full path and joined retirement: " + case) + r"\r?$", output)) != 1:
            raise ValueError("Installed typed full-path native gate omitted its original lifecycle receipt: " + case)
    if len(re.findall(r"^PASS\s*$", output, re.M)) != 1:
        raise ValueError("Installed typed full-path native gate omitted its successful process footer")


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


@contextmanager
def owned_bindings(module, owner, *, workspace=False):
    """Bind only this gate's private module instances to the retained Job owner."""
    original_run = module.CONTROLLER.NATIVE.run
    original_reuse = module.BUILD.reuse
    original_tempfile = getattr(module, "tempfile", None)

    def run(command, *, cwd, env, timeout=180):
        return owner.run(command, cwd=cwd, env=env, timeout=timeout)

    def reuse(*args, **kwargs):
        with owner.preparation():
            return original_reuse(*args, **kwargs)

    temporary = SimpleNamespace(TemporaryDirectory=owner.workspace)
    module.CONTROLLER.NATIVE.run = run
    module.BUILD.reuse = reuse
    if workspace:
        module.tempfile = temporary
    try:
        yield
    finally:
        # Refuse unexpected replacement, without silently overwriting another
        # owner. Restore every attribute still carrying our exact binding.
        changed = []
        for obj, name, expected, original in (
                (module.CONTROLLER.NATIVE, "run", run, original_run),
                (module.BUILD, "reuse", reuse, original_reuse),
                *(((module, "tempfile", temporary, original_tempfile),) if workspace else ())):
            if getattr(obj, name) is expected:
                setattr(obj, name, original)
            else:
                changed.append(name)
        if changed:
            raise RuntimeError("Windows typed gate ownership binding was replaced: " + ", ".join(changed))


def require_originals(receipt):
    if tuple(PREFIX_GATE.CASES) != ORIGINAL_PREFIX_CASES or tuple(SOCKS_GATE.CASES) != ORIGINAL_SOCKS_CASES:
        raise ValueError("Original Windows prefix6/SOCKS8 authoritative inventory changed")
    if (not isinstance(receipt, dict) or receipt.get("schema") != 1 or receipt.get("native") is not True or
            tuple(receipt.get("cases", ())) != ORIGINAL_SOCKS_CASES or receipt.get("typed_full_path") is not True or
            receipt.get("native_joined") is not True or receipt.get("command_job_joined") is not True or
            receipt.get("remote_associations_after_retirement") != 0 or receipt.get("positive_application_and_selected_dns_proved") is not True):
        raise ValueError("Original installed SOCKS8 acceptance is missing or incomplete")
    prefix = receipt.get("original_prefix_acceptance")
    if (not isinstance(prefix, dict) or prefix.get("schema") != 1 or prefix.get("native") is not True or
            tuple(prefix.get("cases", ())) != ORIGINAL_PREFIX_CASES or prefix.get("samples_per_case") != 50 or
            prefix.get("native_down_before_review") is not True or prefix.get("original_final_unreachable") is not True or
            prefix.get("target") != receipt.get("target") or prefix.get("bundle_sha256") != receipt.get("bundle_sha256") or
            prefix.get("source_sha256") != receipt.get("source_sha256")):
        raise ValueError("Original installed prefix6 acceptance is missing or substituted")
    return receipt


def execute(source, bundle, go="go", *, env=None):
    if platform.system() != "Windows" or not ctypes.windll.shell32.IsUserAnAdmin():
        raise ValueError("Installed CONNECT acceptance requires its actual elevated Windows host")
    source, before = sources(source)
    original_socks_receipt = require_originals(SOCKS_GATE.execute(source, bundle, go, env=env))
    owner = COMMAND_OWNER.MAXCommandOwner()
    with owned_bindings(SimpleNamespace(CONTROLLER=CONTROLLER, BUILD=BUILD), owner):
        return execute_typed(source, bundle, go, env, before, original_socks_receipt, owner)


def execute_typed(source, bundle, go, env, before, original_socks_receipt, owner):
    if sources(source)[1] != before:
        raise ValueError("Typed full-path source changed during original prefix6/SOCKS8 preservation")
    compiler, captured, architecture = CONTROLLER.NATIVE.selected_compiler(go, ROOT, dict(os.environ if env is None else env))
    captured["CGO_ENABLED"] = "1"
    target = "windows/" + architecture
    bundle = Path(bundle).resolve()
    original = BUILD.reuse(bundle, target, env=captured)
    original_manifest = hashlib.sha256((bundle / "NATIVE-RUNTIME.json").read_bytes()).hexdigest()
    require_originals(original_socks_receipt)
    if (original_socks_receipt["target"] != target or original_socks_receipt["bundle_sha256"] != original_manifest or
            original_socks_receipt["source_sha256"] != original["policy_sha256"]):
        raise ValueError("CONNECT acceptance changed the original prefix6/SOCKS8 bundle")
    race = ["-race"] if architecture == "amd64" else []
    run = CONTROLLER.NATIVE.run
    with owner.workspace(prefix="routervpn-windows-connect-") as temporary:
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
        peer, controller = work / "connect-peer.test.exe", work / "connect-controller.test.exe"
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
        connect_parent_controls = CONNECT_PARENT.execute(controller, 'windows', run, ROOT, captured)
        child_env = dict(captured, ROUTERVPN_WINDOWS_PREFIX_ROOT=str(installed), ROUTERVPN_WINDOWS_PREFIX_PEER=str(peer))
        status, output = run([controller, "-test.v", "-test.count=1", "-test.timeout=1800s", "-test.run=^" + ROOT_TEST + "$"],
                             cwd=ROOT, env=child_env, timeout=1820)
        if status:
            raise ValueError("Installed typed full-path actual native lifecycle failed:\n" + output[-65536:])
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
                   "typed_full_path": True, "positive_application_and_selected_dns_proved": True,
                   "measurement_bytes_per_direction_per_hop": 8 << 20, "measurement_hops": 3,
                   "native_joined": True, "remote_connect_streams_after_retirement": 0,
                   "command_job_joined": owner.retired, "tun_absent_all_outcomes": True,
                   "public_admission": "closed", "original_socks_acceptance": original_socks_receipt,
                   "sources": before, "scope_sources": native_records, "images": identities,
                   "final_udp_transport": "SS-UoT-v2", "connect_middle_tcp_only": True,
                   "connect_protocols": ["http-connect", "https-connect"], "ordered_latency_samples_per_hop": 50,
                   "typed_connect_parent_controls": connect_parent_controls}
        print(PREFIX + json.dumps(receipt, sort_keys=True), flush=True)
        return receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--go", default="go")
    args = parser.parse_args()
    execute(args.source, args.bundle, args.go)
