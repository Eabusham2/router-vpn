#!/usr/bin/env python3
"""Required original Darwin utun retirement, separate from app acceptance."""
from collections import Counter
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import platform
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "github.com/sagernet/sing-tun"
TAG = "routervpn_darwin_node_chain_native"
TEST_TIMEOUT = "120s"
PROCESS_TIMEOUT = 600
SOURCE_CASES = {
    "TestRouterVPNDarwinNodeChainCloseProgress": ("partial-success", "ambiguous-close", "cancelled-caller", "late-cancel"),
    "TestRouterVPNDarwinNodeChainRouteRetirement": ("partial-retry", "missing", "foreign", "duplicate", "withheld-absence", "cancelled-delete", "replaced-after-retirement"),
    "TestRouterVPNDarwinNodeChainRetirementRequiresOriginal": ("nil", "unbounded", "cancelled", "borrowed", "external", "missing-components"),
}
NATIVE_ROOT = "TestRouterVPNDarwinNodeChainNativeRetirement"
NATIVE_CASES = ("clean", "partial-route", "cancelled-delete", "foreign-descriptor")
SOURCE_SELECTION = "^(" + "|".join(SOURCE_CASES) + ")$"
NATIVE_SELECTION = "^" + NATIVE_ROOT + "$"
TEMPLATES = ("sing_tun_retirement_darwin.go.tmpl", "sing_tun_retirement_darwin_test.go.tmpl", "sing_tun_retirement_darwin_native_test.go.tmpl")
MUTATIONS = (
    ("unowned-route", "if conflict || !exact && !route.attempted {", "if conflict || false {",
     "TestRouterVPNDarwinNodeChainRouteRetirement/missing", "unowned route was deleted or adopted", False),
    ("withheld-absence", 'return errors.New("Darwin original route deletion has no complete absence readback")', "return nil",
     "TestRouterVPNDarwinNodeChainRouteRetirement/withheld-absence", "route deletion passed without native absence", False),
    ("repeated-close", "if step.done {", "if false {",
     "TestRouterVPNDarwinNodeChainCloseProgress/partial-success", "successful original component was closed twice", False),
    ("ambiguous-close", 'return errors.Join(step.failure, errors.New("Darwin native cleanup retains an ambiguous original close"))', "return nil",
     "TestRouterVPNDarwinNodeChainCloseProgress/ambiguous-close", "ambiguous descriptor close was accepted or repeated", False),
    ("foreign-description", "state.file != t.tunFile || ", "",
     NATIVE_ROOT + "/foreign-descriptor", "native cleanup accepted a replacement descriptor object", True),
)


def run(command, *, cwd, env, failure=False):
    result = subprocess.run([str(part) for part in command], cwd=cwd, env=env,
                            capture_output=True, timeout=PROCESS_TIMEOUT)
    output = (result.stdout or b"") + (result.stderr or b"")
    if result.returncode and not failure:
        shown = output if len(output) <= 65536 else output[:32768] + b"\n[bounded native diagnostic]\n" + output[-32768:]
        sys.stderr.write(shown.decode("utf-8", errors="replace"))
        raise subprocess.CalledProcessError(result.returncode, command, result.stdout, result.stderr)
    return result.returncode, output.decode("utf-8", errors="replace").replace("\r\n", "\n")


def expected(cases):
    return Counter(name for root, leaves in cases.items() for name in (root, *(root + "/" + leaf for leaf in leaves)))


def events(output):
    result = []
    for line in output.splitlines():
        try:
            event = json.loads(line)
        except (ValueError, TypeError):
            raise ValueError("Native retirement omitted complete test2json events") from None
        if not isinstance(event, dict) or event.get("Package") != PACKAGE:
            raise ValueError("Native retirement changed its original package")
        result.append(event)
    if not result or any("WARNING: DATA RACE" in str(event.get("Output", "")) for event in result):
        raise ValueError("Native retirement omitted events or reported a race")
    return result


def complete_receipt(output):
    observed = events(output)
    if observed[0].get("Action") != "start" or observed[0].get("Test"):
        raise ValueError("Native retirement omitted its original package start")
    states, runs, passes, failures = {}, Counter(), Counter(), Counter()
    ended = None
    for position, event in enumerate(observed):
        action, name = event.get("Action"), event.get("Test")
        if ended is not None:
            raise ValueError("Native retirement emitted events after its package end")
        if not name:
            if action == "start":
                if position != 0:
                    raise ValueError("Native retirement repeated its package start")
            elif action == "output":
                pass
            elif action in ("pass", "fail"):
                if position != len(observed)-1 or not states or any(state == "run" for state in states.values()):
                    raise ValueError("Native retirement truncated or reordered its package end")
                if (action == "pass") != (not failures):
                    raise ValueError("Native retirement package result contradicts its original tests")
                ended = action
            else:
                raise ValueError("Native retirement has an unexpected package event")
            continue
        if not isinstance(name, str):
            raise ValueError("Native retirement changed its test identity")
        if action == "run":
            if name in states or "/" in name and states.get(name.rsplit("/", 1)[0]) != "run":
                raise ValueError("Native retirement repeated or reordered a test start")
            states[name] = "run"
            runs[name] += 1
        elif action == "output":
            if states.get(name) != "run":
                raise ValueError("Native retirement output escaped its original running test")
        elif action in ("pass", "fail"):
            if states.get(name) != "run" or any(value == "run" and child.startswith(name + "/") for child, value in states.items()):
                raise ValueError("Native retirement test ended without its original joined run")
            if action == "pass" and any(child.startswith(name + "/") for child in failures):
                raise ValueError("Native retirement parent passed after a failed child")
            states[name] = action
            (passes if action == "pass" else failures)[name] += 1
        else:
            raise ValueError("Native retirement skipped or changed an original test")
    if ended is None:
        raise ValueError("Native retirement omitted its final package result")
    return observed, runs, passes, failures, ended


def require_pass(output, cases):
    _, runs, passes, failures, ended = complete_receipt(output)
    wanted = expected(cases)
    if ended != "pass" or failures or runs != wanted or passes != wanted:
        raise ValueError("Native retirement changed its exact required run/pass inventory")
    return sum(passes.values())


def require_rejection(code, output, witness, message):
    observed, runs, passes, failures, ended = complete_receipt(output)
    root, leaf = witness.split("/", 1)
    wanted = expected({root: (leaf,)})
    text = "".join(str(event.get("Output", "")) for event in observed if event.get("Test") == witness)
    if code != 1 or ended != "fail" or runs != wanted or failures != wanted or passes or message not in text:
        raise ValueError("Native retirement negative control did not fail its original complete witness")


def discover(output):
    roots = output.splitlines()
    wanted = set(SOURCE_CASES) | {NATIVE_ROOT}
    if len(roots) != len(set(roots)) or set(roots) != wanted:
        raise ValueError("Compiled Darwin retirement roots changed")


def load_preparer():
    spec = importlib.util.spec_from_file_location("darwin_retirement_prepare", ROOT / "deploy/prepare-desktop-mtu.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def checked_source(source, env):
    if platform.system() != "Darwin":
        raise ValueError("Darwin retirement requires its actual native host")
    source = source.resolve()
    module = source / "routervpn-desktop-tun"
    _, version = run(["go", "env", "GOVERSION", "GOOS", "GOARCH", "GOMODCACHE"], cwd=module, env=env)
    values = version.strip().splitlines()
    cpu = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "amd64", "AMD64": "amd64"}.get(platform.machine())
    if len(values) != 4 or values[:3] != ["go1.26.3", "darwin", cpu]:
        raise ValueError("Darwin retirement changed its pinned compiler or host architecture")
    _, pin = run(["git", "-C", source, "rev-parse", "HEAD"], cwd=module, env=env)
    if pin.strip() != "1ac1a339cb1223e9c70eae14c44411c75033c02d":
        raise ValueError("Darwin retirement changed its original core pin")
    prep = load_preparer()
    pristine = Path(values[3]) / "github.com/sagernet/sing-tun@v0.9.3/tun_darwin.go"
    original = prep.network_receipt_patch("tun_darwin.go", prep.darwin_owned_source(pristine.read_bytes()))
    projected = module / "tun_darwin.go"
    if projected.is_symlink() or projected.read_bytes() != original:
        raise ValueError("Darwin retirement lost its complete pinned native constructor")
    digest = hashlib.sha256(original)
    for name in TEMPLATES:
        template = ROOT / "mobile/desktop" / name
        target = module / ("routervpn_" + name.removesuffix(".tmpl"))
        if template.is_symlink() or target.is_symlink() or target.read_bytes() != template.read_bytes():
            raise ValueError("Darwin retirement template differs from its original prepared source")
        digest.update(name.encode() + b"\0" + target.read_bytes())
    return module, digest.hexdigest()


def compile_image(module, image, tags, env):
    run(["go", "test", "-c", "-race", "-mod=readonly", "-ldflags=-checklinkname=0", "-tags=" + tags,
         "-o", image, "."], cwd=module, env=env)


def execute(module, image, selection, env, *, native=False, failure=False):
    child = [image, "-test.v", "-test.run=" + selection, "-test.count=1", "-test.timeout=" + TEST_TIMEOUT]
    if native:
        child = (["sudo", "-n", "--", "env"] if os.geteuid() != 0 else ["env"]) + ["ROUTERVPN_DARWIN_NODE_CHAIN_NATIVE=1", *child]
    return run(["go", "tool", "test2json", "-p", PACKAGE, "-t", *child], cwd=module, env=env, failure=failure)


def check(source, tags=""):
    env = os.environ.copy()
    module, source_hash = checked_source(source, env)
    selected = ",".join(dict.fromkeys(filter(None, [*tags.split(","), TAG])))
    target = module / "routervpn_sing_tun_retirement_darwin.go"
    original = target.read_bytes()
    with tempfile.TemporaryDirectory(prefix="routervpn-darwin-retirement-") as directory:
        image = Path(directory) / "retirement.test"
        compile_image(module, image, selected, env)
        _, listing = run([image, "-test.list=^TestRouterVPNDarwinNodeChain"], cwd=module, env=env)
        discover(listing.strip())
        source_code, baseline = execute(module, image, SOURCE_SELECTION, env)
        if source_code != 0:
            raise ValueError("Darwin source tests did not exit successfully")
        source_verdicts = require_pass(baseline, SOURCE_CASES)
        native_code, native = execute(module, image, NATIVE_SELECTION, env, native=True)
        if native_code != 0:
            raise ValueError("Darwin native tests did not exit successfully")
        native_verdicts = require_pass(native, {NATIVE_ROOT: NATIVE_CASES})
        image_hash = hashlib.sha256(image.read_bytes()).hexdigest()
        for label, before, after, witness, message, privileged in MUTATIONS:
            raw = original.decode("utf-8")
            if raw.count(before) != 1:
                raise ValueError("Darwin retirement causal boundary changed: " + label)
            try:
                target.write_bytes(raw.replace(before, after, 1).encode("utf-8"))
                broken = Path(directory) / (label + ".test")
                compile_image(module, broken, selected, env)
                root, leaf = witness.split("/", 1)
                code, output = execute(module, broken, "^" + root + "$/^" + leaf + "$", env,
                                       native=privileged, failure=True)
                require_rejection(code, output, witness, message)
                print("Rejected Darwin retirement control: " + label, flush=True)
            finally:
                target.write_bytes(original)
        _, verified = checked_source(source, env)
        if verified != source_hash:
            raise ValueError("Darwin retirement did not restore the exact original source")
        receipt = {"schema": 1, "kind": "darwin-original-native-retirement-v1",
                   "source_sha256": source_hash, "race_image_sha256": image_hash,
                   "source_verdicts": source_verdicts, "native_verdicts": native_verdicts,
                   "causal_controls": len(MUTATIONS)}
        print("Native Darwin original retirement: " + json.dumps(receipt, sort_keys=True), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--tags", default="")
    arguments = parser.parse_args()
    check(arguments.source, arguments.tags)
