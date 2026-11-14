#!/usr/bin/env python3
"""Verify both original and typed generated Darwin native child invocations."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import platform
import re
import shutil
import sys
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
SUITE = "darwin-socks-child"
HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")
ORIGINAL = ("wg-three", "mixed-four", "captured-mtu", "mtu-rollback", "wrong-middle-key",
            "wrong-middle-proof", "final-dns-failure", "foreign-mtu-session")
TYPED = ("run-wg", "run-awg-fast", "run-awg-strong", "middle-password",
         "final-token", "selected-dns", "middle-public", "held-proof-stop")
HARNESS = "TestRouterVPNNodeChainSOCKSDarwinNativeHarness"
NATIVE = "TestRouterVPNNodeChainSOCKSDarwinNativeCommand"
REQUIRED_SOURCES = frozenset({
    "cmd/sing-box/routervpn_node_chain_socks_command_darwin_native_test.go",
    "cmd/sing-box/routervpn_node_chain_socks_command.go",
    "cmd/sing-box/routervpn_node_chain_socks_run_darwin.go",
    "cmd/sing-box/routervpn_node_chain_socks_control_darwin.go",
    "cmd/sing-box/routervpn_node_chain_socks_retirement_darwin.go",
    "routervpn/macosprocess/node_chain_socks_transfer.go",
    "protocol/routervpnamnezia/routervpn_node_chain_socks_peer_darwin_test.go",
    "protocol/routervpnamnezia/routervpn_node_chain_socks_process_darwin_test.go",
})

def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value

CORE = module("darwin_socks_trusted_process", ROOT/"deploy/test_focused_multihop_clocks.py")
IDENTITY = module("darwin_socks_trusted_identity", ROOT/"deploy/focused_source_identity.py")
BASE = module("darwin_socks_trusted_original", ROOT/"deploy/test_darwin_node_child_tun.py")

def digest(data):
    return hashlib.sha256(data).hexdigest()

def selection(source, source_sha, output):
    path = output.parent/"selection.json"
    if not HEX40.fullmatch(source_sha) or path.is_symlink() or not path.is_file():
        raise ValueError("Original exact source selection is missing")
    raw = path.read_bytes()
    value = json.loads(raw)
    if type(value.get("schema")) is not int or value["schema"] != 1 or value.get("suite") != SUITE or value.get("source_sha") != source_sha or value.get("validation_scope") != "read-only-source-candidate":
        raise ValueError("Original source selection changed purpose")
    for key in ("validator_sha", "validator_tree", "base_sha", "base_tree", "source_sha", "source_tree"):
        if not isinstance(value.get(key), str) or not HEX40.fullmatch(value[key]):
            raise ValueError("Original source selection lost Git identity")
    IDENTITY.original_checkout(ROOT, value["validator_sha"])
    IDENTITY.original_checkout(source, source_sha)
    for path, commit, tree in ((ROOT, value["validator_sha"], value["validator_tree"]),
                              (source, source_sha, value["source_tree"])):
        if CORE.git(path, "rev-parse", "HEAD").decode().strip() != commit or CORE.git(path, "rev-parse", "HEAD^{tree}").decode().strip() != tree:
            raise ValueError("Original checkout changed commit or tree")
    return value, raw

def source_receipt(value):
    records = value.get("source_files")
    if not isinstance(records, dict) or not records or any(not isinstance(k, str) or not isinstance(v, str) or not HEX64.fullmatch(v) for k, v in records.items()):
        raise ValueError("Original native source inventory is absent")
    if digest(json.dumps(records, sort_keys=True, separators=(",", ":")).encode()) != value.get("source_sha256"):
        raise ValueError("Original native source digest differs")
    return records

def image_receipt(value, name):
    images = value.get("artifacts")
    image = images.get(name) if isinstance(images, dict) else None
    if not isinstance(image, dict) or set(image) != {"bytes", "sha256"} or type(image["bytes"]) is not int or image["bytes"] <= 0 or not isinstance(image["sha256"], str) or not HEX64.fullmatch(image["sha256"]):
        raise ValueError("Original native image receipt differs")
    return image

def require_native(value, arch, metadata, outputs):
    if type(value.get("schema")) is not int or value["schema"] != 1 or value.get("gate") != "generated-darwin-ordered-socks-child" or value.get("scope") != "actual-generated-command-pf-utun" or value.get("target") != "darwin/"+arch or value.get("toolchain") != BASE.UID.RACE.TOOLCHAIN or value.get("cases") != list(TYPED) or value.get("public_darwin_admission") != "closed" or "native_accepted" in value:
        raise ValueError("Typed native receipt lost its original scope")
    if value.get("repository") != {"repository":"Eabusham2/router-vpn", "commit":metadata["source_sha"], "tree":metadata["source_tree"]}:
        raise ValueError("Native receipt substituted the original repository")
    original = value.get("original_eight")
    if not isinstance(original, dict) or type(original.get("schema")) is not int or original["schema"] != 1 or original.get("gate") != "generated-darwin-ordered-child" or original.get("scope") != "generated-command-utun" or original.get("target") != "darwin/"+arch or original.get("cases") != list(ORIGINAL) or original.get("toolchain") != BASE.UID.RACE.TOOLCHAIN or "native_accepted" in original:
        raise ValueError("Original eight native cases were replaced")
    if original.get("pins") != {"sing-box":BASE.BUILD.PIN, "xray":BASE.BUILD.POLICY.XRAY.XRAY_PIN}:
        raise ValueError("Original native source pins changed")
    typed_sources, original_sources = source_receipt(value), source_receipt(original)
    if not REQUIRED_SOURCES.issubset(typed_sources):
        raise ValueError("Typed native source closure omitted its original owner")
    extra = {"gate/test_darwin_socks_child_tun.py", "gate/test_darwin_socks_child_tun_runner.py"}
    if set(typed_sources)-set(original_sources) != extra or any(typed_sources.get(k) != v for k, v in original_sources.items()):
        raise ValueError("Two native invocations used different original sources")
    for name in ("generated-child-test",):
        if image_receipt(value, name) != image_receipt(original, name):
            raise ValueError("Two native invocations used different child images")
    if image_receipt(value, "independent-encrypted-peer") != image_receipt(original, "independent-ordered-peer"):
        raise ValueError("Two native invocations used different peer images")
    if len(outputs) != 2:
        raise ValueError("Original two native invocations were omitted or repeated")
    BASE._check_selected_verdict(outputs[0], BASE.HARNESS, BASE.NATIVE, ORIGINAL)
    BASE._check_selected_verdict(outputs[1], HARNESS, NATIVE, TYPED)
    if [digest(s.encode()) for s in outputs] != [original.get("output_sha256"), value.get("output_sha256")]:
        raise ValueError("Native transcript differs from original acceptance receipt")

def validate(source, source_sha, output, go="go"):
    if platform.system() != "Darwin" or platform.machine() not in ("x86_64", "arm64"):
        raise ValueError("Actual matching Darwin native host is required")
    arch = {"x86_64":"amd64", "arm64":"arm64"}[platform.machine()]
    source, output = Path(source).resolve(strict=True), Path(output).absolute()
    if output.exists() or output.is_symlink() or source == output or source in output.parents:
        raise ValueError("Native evidence must be fresh and outside candidate")
    metadata, selected = selection(source, source_sha, output)
    before = CORE.snapshot(source)
    output.mkdir(mode=0o700)
    (output/"source-before.json").write_text(json.dumps(before, sort_keys=True)+"\n")
    receipt = {"schema":1, "suite":SUITE, "selection":metadata, "target":"darwin/"+arch,
               "accepted":False, "public_darwin_admission":"closed", "installed_controller_accepted":False}
    outputs = []
    gate = module("darwin_socks_candidate_gate", source/"deploy/test_darwin_socks_child_tun.py")
    if tuple(gate.CASES) != TYPED or tuple(gate.BASE.CASES) != ORIGINAL or gate.HARNESS != HARNESS or gate.NATIVE != NATIVE:
        raise ValueError("Candidate changed the fixed original native inventory")
    compiler = shutil.which(go)
    if compiler is None:
        raise ValueError("Pinned Go compiler is missing")
    captured = dict(os.environ, CGO_ENABLED="1", GOTOOLCHAIN="local", GOWORK="off", GOFLAGS="-p=2 -mod=readonly",
                    GOMAXPROCS="2", GOGC="100", GOMEMLIMIT="2GiB", PYTHONDONTWRITEBYTECODE="1",
                    ROUTERVPN_DARWIN_NODE_CHILD_ACCEPTANCE="1", ROUTERVPN_DARWIN_SOCKS_CHILD_ACCEPTANCE="1")
    original_output = gate.BASE.native_output
    def observed(command, **kwargs):
        name = "native-original" if len(outputs) == 0 else "native-socks"
        try:
            text = original_output(command, **kwargs)
        except BaseException as failure:
            raw = getattr(failure, "output", b"")
            if isinstance(raw, str): raw = raw.encode()
            (output/(name+"-failure.log")).write_bytes(raw or (type(failure).__name__+": "+str(failure)).encode())
            raise
        (output/(name+".log")).write_text(text)
        outputs.append(text)
        return text
    gate.BASE.native_output = observed
    started = time.monotonic()
    try:
        value = gate.standalone(str(compiler), environment=captured, required_commit=source_sha, receipt=output/"native-receipt.json")
        require_native(value, arch, metadata, outputs)
        if CORE.snapshot(source) != before or selection(source, source_sha, output) != (metadata, selected):
            raise ValueError("Original candidate changed during native execution")
        after = CORE.snapshot(source)
        (output/"source-after.json").write_text(json.dumps(after, sort_keys=True)+"\n")
        receipt.update(accepted=True, cases=list(TYPED), original_cases=list(ORIGINAL),
                       native_receipt_sha256=digest((output/"native-receipt.json").read_bytes()),
                       native_scope="generated-command-pf-utun", source_files=len(before))
    except BaseException as failure:
        receipt["failure_type"] = type(failure).__name__
        raise
    finally:
        gate.BASE.native_output = original_output
        receipt["seconds"] = time.monotonic()-started
        receipt["logs"] = {p.name:digest(p.read_bytes()) for p in sorted(output.glob("*.log"))}
        (output/"manifest.json").write_text(json.dumps(receipt, indent=2, sort_keys=True)+"\n")
    return receipt

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--go", default="go")
    args = parser.parse_args()
    print(json.dumps(validate(args.source, args.source_sha, args.output, args.go), sort_keys=True))
