#!/usr/bin/env python3
"""Execute every original native Box root once, from one retained test image.

Compiler, process and target-specific Go test bounds remain unchanged. Family
phases separate accumulated component work; they do not grant native admission
or substitute component fixtures for installed/device acceptance.
"""
from pathlib import Path
import hashlib
import importlib.util
import json
import re
import stat
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
SELECTION = r"^TestRouterVPN(Desktop(Tor|External|NodeChain)|NodeChain|Execution)"
PROCESS_TIMEOUT = 600
FAMILIES = ("desktop-tor", "desktop-external", "desktop-node-chain", "candidate-preparation", "node-chain", "execution")
PACKAGE = "github.com/sagernet/sing-box"

# These roots remain invoked on every desktop. Their original first-statement
# GOOS guards explicitly report other-platform coverage as skipped, not passed.
# Bind each exception to its exact generated source, guard and diagnostic.
PLATFORM_SKIP_SOURCES = (
    ("routervpn_desktop_tor_box_physical_test.go", ("darwin", "windows"),
     'if runtime.GOOS != "linux" {', "Linux isolated socket factory", (
         "TestRouterVPNDesktopTorPhysicalBoxCapturesExactFactoryBeforeStartup",
         "TestRouterVPNDesktopTorPhysicalBoxRefusesUnprovisionedStart",
         "TestRouterVPNDesktopTorFixedPhysicalBoxRequiresCapturedFactory",
         "TestRouterVPNDesktopTorPhysicalRegistrationContext")),
    ("routervpn_desktop_node_chain_box_physical_test.go", ("darwin",),
     'if runtime.GOOS != "linux" && runtime.GOOS != "windows" {', "this physical adapter covers Linux and Windows", (
         "TestRouterVPNDesktopNodeChainPhysicalRejectsSubstitutedBox",
         "TestRouterVPNDesktopNodeChainPhysicalAWGModesAndOriginalBox")),
    ("routervpn_desktop_external_box_integration_test.go", ("darwin",),
     'if runtime.GOOS != "linux" && runtime.GOOS != "windows" {', "ordinary native physical admission requires Linux or Windows", (
         "TestRouterVPNDesktopExternalPhysicalIntegration",)),
)


def platform_skips(source, target, roots):
    allowed = {}
    for filename, systems, guard, reason, names in PLATFORM_SKIP_SOURCES:
        if target.split("/")[0] not in systems:
            continue
        selected = [name for name in names if name in roots]
        if not selected:
            continue
        path = source / filename
        if path.is_symlink() or not path.is_file():
            raise ValueError("Native Box platform applicability lost its original source")
        text = path.read_text(encoding="utf-8")
        for name in selected:
            boundary = 'func ' + name + '(t *testing.T) {\n\t' + guard + '\n\t\tt.Skip("' + reason + '")\n\t}'
            if text.count(boundary) != 1 or name in allowed:
                raise ValueError("Native Box platform applicability changed its exact original guard")
            allowed[name] = reason
    return allowed


def load_receipt():
    spec = importlib.util.spec_from_file_location("native_root_phase_receipt", ROOT / "deploy/test_desktop_darwin_retirement.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.PACKAGE = PACKAGE
    return module


def partition(listing, complete_listing):
    roots = listing.strip().splitlines()
    complete = complete_listing.strip().splitlines()
    if not complete or len(complete) != len(set(complete)) or roots != [name for name in complete if re.match(SELECTION, name)]:
        raise ValueError("Native Box discovery omitted or duplicated an original compiled root")
    if not roots or len(roots) != len(set(roots)) or any(not re.fullmatch(r"Test[A-Za-z0-9_]+", name) or not re.match(SELECTION, name) for name in roots):
        raise ValueError("Native Box discovery lost its exact original roots")
    groups = {name: [] for name in FAMILIES}
    for name in roots:
        if name.startswith("TestRouterVPNDesktopTor"):
            family = "desktop-tor"
        elif name.startswith("TestRouterVPNDesktopExternal"):
            family = "desktop-external"
        elif name.startswith("TestRouterVPNDesktopNodeChain"):
            family = "desktop-node-chain"
        elif name.startswith("TestRouterVPNNodeChainCandidatePreparation"):
            family = "candidate-preparation"
        elif name.startswith("TestRouterVPNNodeChain"):
            family = "node-chain"
        elif name.startswith("TestRouterVPNExecution"):
            family = "execution"
        else:
            raise ValueError("Native Box root has no original family")
        groups[family].append(name)
    flattened = [name for group in groups.values() for name in group]
    if any(not group for group in groups.values()) or len(flattened) != len(roots) or set(flattened) != set(roots):
        raise ValueError("Native Box family partition omitted or duplicated a compiled root")
    return groups


def require_phase(output, required, allowed=None):
    allowed = {} if allowed is None else allowed
    if set(allowed) - set(required):
        raise ValueError("Native Box phase borrowed another platform applicability receipt")
    validator = load_receipt()
    observed = validator.events(output)
    for name, reason in allowed.items():
        records = [event for event in observed if event.get("Test") == name or str(event.get("Test", "")).startswith(name + "/")]
        actions = [event.get("Action") for event in records if event.get("Action") != "output"]
        if (actions != ["run", "skip"] or any(event.get("Test") != name for event in records) or
                not any(str(event.get("Output", "")).strip().endswith(": " + reason) for event in records)):
            raise ValueError("Native Box phase lost its exact original platform skip receipt")
        indices = [index for index, event in enumerate(observed) if event.get("Test") == name]
        if not indices or indices[0] == 0 or indices[-1] == len(observed)-1 or any(
                event.get("Action") in ("start", "pass", "fail") and not event.get("Test")
                for event in observed[indices[0]:indices[-1]+1]):
            raise ValueError("Native Box platform skip escaped its original package lifetime")
    # Preserve authorized skip records separately. They never become fabricated
    # pass events and never relax the strict parser for another root or child.
    filtered = [event for event in observed if event.get("Test") not in allowed]
    _, runs, passes, failures, ended = validator.complete_receipt("\n".join(json.dumps(event) for event in filtered))
    roots = {name for name in runs if "/" not in name}
    if ended != "pass" or failures or roots != set(required) - set(allowed) or any(runs[name] != 1 or passes[name] != 1 for name in runs):
        raise ValueError("Native Box phase did not pass every applicable original root and child")
    return len(passes)


def source_digest(source):
    # The already prepared engine owns its generated and patched source trees.
    # Keep all its original Go inputs, including local replacement go.mod/sum,
    # bound throughout compilation, discovery and every family invocation.
    records = {}
    for path in sorted(source.rglob("*")):
        relative = path.relative_to(source)
        if ".git" in relative.parts or path.suffix != ".go" and path.name not in ("go.mod", "go.sum"):
            continue
        if path.is_symlink() or not path.is_file():
            raise ValueError("Native Box source is not an original regular file")
        records[str(relative)] = hashlib.sha256(path.read_bytes()).hexdigest()
    if "go.mod" not in records or not any(name.endswith(".go") for name in records):
        raise ValueError("Native Box source inventory is empty")
    return hashlib.sha256(json.dumps(records, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def image_identity(image):
    def identity(value):
        if not stat.S_ISREG(value.st_mode) or value.st_nlink != 1:
            raise ValueError("Native Box image is not its original regular file")
        return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns
    if image.is_symlink():
        raise ValueError("Native Box image is linked")
    before = identity(image.stat())
    digest = hashlib.sha256(image.read_bytes()).hexdigest()
    if identity(image.stat()) != before:
        raise ValueError("Native Box image changed during original readback")
    return before, digest


def execute(source, target, tags, env, runner):
    if target not in ("linux/amd64", "linux/arm64", "darwin/amd64", "darwin/arm64", "windows/amd64", "windows/arm64"):
        raise ValueError("Native Box phases require an original desktop target")
    source, captured = source.resolve(), dict(env)
    if (captured.get("GOOS"), captured.get("GOARCH")) != tuple(target.split("/")):
        raise ValueError("Native Box phases changed their captured target")
    original = source_digest(source)
    timeout = "180s" if target.startswith("linux/") else "120s"
    race = [] if target == "windows/arm64" else ["-race"]
    with tempfile.TemporaryDirectory(prefix="routervpn-native-box-phases-") as directory:
        image = Path(directory) / ("original.test.exe" if target.startswith("windows/") else "original.test")
        runner(["go", "test", "-c", *race, "-mod=readonly", "-tags=" + tags,
                "-ldflags=-checklinkname=0", "-o", image, "."],
               cwd=source, env=captured, timeout=PROCESS_TIMEOUT)
        retained = image_identity(image)
        def unchanged():
            if captured != env or source_digest(source) != original or image_identity(image) != retained:
                raise ValueError("Native Box phase changed its original source, environment or image")
        unchanged()
        listing = runner([image, "-test.list=" + SELECTION], cwd=source, env=captured, timeout=PROCESS_TIMEOUT)
        unchanged()
        complete_listing = runner([image, "-test.list=."], cwd=source, env=captured, timeout=PROCESS_TIMEOUT)
        groups = partition(listing, complete_listing)
        unchanged()
        skipped = platform_skips(source, target, [name for group in groups.values() for name in group])
        completed, verdicts = [], {}
        for family in FAMILIES:
            unchanged()
            started = time.monotonic()
            print("Native Box family start: " + family, flush=True)
            selection = "^(" + "|".join(re.escape(name) for name in groups[family]) + ")$"
            output = runner(["go", "tool", "test2json", "-p", PACKAGE, "-t", image,
                             "-test.v", "-test.run=" + selection, "-test.count=1", "-test.timeout=" + timeout],
                            cwd=source, env=captured, timeout=PROCESS_TIMEOUT)
            count = require_phase(output, groups[family], {name: reason for name, reason in skipped.items() if name in groups[family]})
            unchanged()
            completed.extend(groups[family])
            verdicts[family] = count
            print("Native Box family passed: " + family + " (%d verdicts; %.3fs)" % (count, time.monotonic() - started), flush=True)
        wanted = [name for group in groups.values() for name in group]
        if completed != wanted or len(completed) != len(set(completed)) or tuple(verdicts) != FAMILIES:
            raise ValueError("Native Box completion omitted an original family")
        unchanged()
        result = {"kind": "native-box-family-phases-v1", "target": target, "tags": tags,
                  "race": bool(race), "source_sha256": original, "image_sha256": retained[1],
                  "test_timeout": timeout, "roots": completed, "verdicts": verdicts, "platform_skips": skipped}
        print("Complete native Box families: " + json.dumps(result, sort_keys=True), flush=True)
        return result
