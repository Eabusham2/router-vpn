#!/usr/bin/env python3
"""Bind independent native Windows phases to one required CI source/run.

Each job retains the native phase's existing compiler, test and cleanup limits.
The aggregate requires all seven phases on both architectures, original image
receipts, and one prepared-source closure per architecture. A receipt is CI
evidence, not an installed package or physical-device acceptance record.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import re
import stat
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("windows_native_phase", ROOT / "deploy/test_windows_node_physical.py")
NATIVE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NATIVE)
ARCHITECTURES = ("amd64", "arm64")
FORMAT = "routervpn-windows-physical-ci-v1"
SOURCE_FORMAT = "routervpn-windows-node-bootstrap-ci-v1"


def context(env):
    values = {key: env.get(name, "") for key, name in (
        ("repository", "GITHUB_REPOSITORY"), ("commit", "GITHUB_SHA"),
        ("run_id", "GITHUB_RUN_ID"), ("run_attempt", "GITHUB_RUN_ATTEMPT"))}
    if (not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", values["repository"]) or
            not re.fullmatch(r"[0-9a-f]{40}", values["commit"]) or
            any(not re.fullmatch(r"[1-9][0-9]{0,19}", values[key]) for key in ("run_id", "run_attempt"))):
        raise ValueError("Windows native CI requires the original repository, commit and workflow run")
    return values


def verify_checkout(expected):
    def git(*arguments):
        return subprocess.check_output(["git", *arguments], cwd=ROOT, text=True, timeout=30).strip()
    if git("rev-parse", "HEAD") != expected["commit"] or git("status", "--porcelain", "--untracked-files=no"):
        raise ValueError("Windows native CI checkout differs from the exact workflow source")


def filename(architecture, phase):
    if architecture not in ARCHITECTURES or phase not in NATIVE.PHASES:
        raise ValueError("Windows native CI requires an exact architecture and phase")
    return "windows-physical-" + architecture + "-" + phase + ".json"


def read_receipt(path):
    path = Path(path)
    if (path.is_symlink() or not path.is_file() or not stat.S_ISREG(path.stat().st_mode) or
            path.stat().st_size > 32768):
        raise ValueError("Windows native CI receipt is not an original bounded regular file")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Windows native CI receipt repeats a field")
            result[key] = value
        return result
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique)


def comparable_source(source, records, compiler, env):
    """Normalize only the verified sibling Xray location, retaining every byte.

    The original raw go.mod hash remains in the native phase receipt. All other
    module bytes, copied sources and the pinned Xray source enter this second
    closure, so independent temporary roots can be compared without ignoring a
    dependency or accepting a foreign local replacement.
    """
    source = Path(source).resolve()
    xray = source.parent / "xray"
    module = source / "go.mod"
    if source.name != "core" or module.is_symlink() or xray.is_symlink() or not xray.is_dir():
        raise ValueError("Windows native CI lost its owned core and sibling Xray paths")
    raw = module.read_bytes()
    if records.get("go.mod") != hashlib.sha256(raw).hexdigest():
        raise ValueError("Windows native CI module differs from its original raw source receipt")
    parsed = json.loads(subprocess.check_output([str(compiler), "mod", "edit", "-json"], cwd=source, env=env, timeout=30))
    selected = []
    for replacement in parsed.get("Replace", []):
        old, new = replacement["Old"], replacement["New"]
        if old["Path"] == "github.com/xtls/xray-core":
            if old.get("Version") or new.get("Version") or not Path(new["Path"]).is_absolute() or Path(new["Path"]).resolve() != xray:
                raise ValueError("Windows native CI Xray replacement is not its exact owned sibling")
            selected.append(new["Path"])
        elif not new.get("Version"):
            path = Path(new["Path"])
            if path.is_absolute() or not (source / path).resolve().is_relative_to(source):
                raise ValueError("Windows native CI contains a foreign local module replacement")
    matches = list(re.finditer(rb"(?m)^replace github\.com/xtls/xray-core => ([^\r\n]+)\r?$", raw))
    if len(selected) != 1 or len(matches) != 1:
        raise ValueError("Windows native CI requires one exact original Xray replacement")
    token = matches[0].group(1).decode("utf-8")
    if (json.loads(token) if token.startswith('"') else token) != selected[0]:
        raise ValueError("Windows native CI Xray module token differs from the parsed dependency")
    start, end = matches[0].span(1)
    normalized = raw[:start] + b"../xray" + raw[end:]
    comparable = dict(records, **{"go.mod": hashlib.sha256(normalized).hexdigest()})
    go_sources = NATIVE.NODE.xray_reference_sources(xray)
    xray_sources, _ = NATIVE.NODE.complete_xray_source_tree(xray, NATIVE.NODE.PREP.RELAY.XRAY.XRAY_PIN, go_sources)
    for name, digest in xray_sources.items():
        key = "ci-xray/" + name
        if key in comparable:
            raise ValueError("Windows native CI Xray source identity overlaps another owner")
        comparable[key] = digest
    if module.read_bytes() != raw:
        raise ValueError("Windows native CI module changed during dependency observation")
    return NATIVE.source_digest(comparable)


def validate_context(value, expected, receipt_format):
    fields = {"format", *expected, "native", "comparable_source_sha256"}
    if receipt_format == SOURCE_FORMAT:
        fields.add("original_module_sha256")
    if (not isinstance(value, dict) or set(value) != fields or
            value["format"] != receipt_format or any(value[key] != expected[key] for key in ("repository", "commit", "run_id")) or
            not isinstance(value["run_attempt"], str) or not re.fullmatch(r"[1-9][0-9]{0,19}", value["run_attempt"]) or
            int(value["run_attempt"]) > int(expected["run_attempt"])):
        raise ValueError("Windows native CI receipt belongs to another source or workflow run")
    if not isinstance(value["comparable_source_sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", value["comparable_source_sha256"]):
        raise ValueError("Windows native CI receipt has no comparable prepared-source identity")
    native = value["native"]
    if not isinstance(native, dict) or not isinstance(native.get("source_sha256"), str):
        raise ValueError("Windows native CI receipt has no prepared-source identity")
    return native


def validate(value, expected, architecture, phase):
    native = validate_context(value, expected, FORMAT)
    NATIVE.validate_phase_receipt(native, phase, native["source_sha256"], architecture)
    return native


def run_phase(architecture, phase, destination, go="go", *, env=None):
    expected = context(os.environ if env is None else env)
    destination = Path(destination)
    if destination.name != filename(architecture, phase) or destination.exists() or destination.is_symlink():
        raise ValueError("Windows native CI receipt must be a new owned phase path")
    verify_checkout(expected)
    observed = []
    def selected(source, compiler, **kwargs):
        source, before = NATIVE.checked_sources(source)
        comparable = comparable_source(source, before, compiler, kwargs["env"])
        native = NATIVE.execute(source, compiler, phase=phase, **kwargs)
        if (native["source_sha256"] != NATIVE.source_digest(before) or NATIVE.checked_sources(source)[1] != before or
                comparable_source(source, before, compiler, kwargs["env"]) != comparable):
            raise ValueError("Windows native CI original source or Xray dependency changed during its phase")
        value = {"format": FORMAT, **expected, "native": native, "comparable_source_sha256": comparable}
        validate(value, expected, architecture, phase)
        observed.append(value)
    NATIVE.BOOT.standalone(go, native_test=selected)
    if len(observed) != 1:
        raise ValueError("Windows native CI preparation did not execute its original phase exactly once")
    value = observed[0]
    verify_checkout(expected)
    with destination.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True)
        stream.write("\n")
    return value


def aggregate(directory, needs_result, *, env=None):
    if needs_result != "success":
        raise ValueError("Windows native CI completion requires every matrix job to succeed")
    expected = context(os.environ if env is None else env)
    verify_checkout(expected)
    directory = Path(directory)
    names = {filename(architecture, phase) for architecture in ARCHITECTURES for phase in NATIVE.PHASES}
    if directory.is_symlink() or not directory.is_dir() or {p.name for p in directory.iterdir()} != names:
        raise ValueError("Windows native CI completion requires exactly fourteen phase receipts")
    results = {}
    for architecture in ARCHITECTURES:
        phases, closures = [], set()
        for phase in NATIVE.PHASES:
            value = read_receipt(directory / filename(architecture, phase))
            phases.append(validate(value, expected, architecture, phase))
            closures.add(value["comparable_source_sha256"])
        if len(closures) != 1:
            raise ValueError("Windows native CI phases have different prepared-source closures")
        results[architecture] = phases
    verify_checkout(expected)
    print("Windows native CI: all seven original phases passed on AMD64 and ARM64 for " + expected["commit"], flush=True)
    return results


def source_filename(architecture, phase):
    if architecture not in ARCHITECTURES or phase not in NATIVE.NODE.BOOTSTRAP_SOURCE_PHASES:
        raise ValueError("Unknown standalone Windows source phase or architecture")
    return f"windows-startup-{architecture}-{phase}.json"


def standalone_source(architecture, *, phase=None, destination=None, directory=None, needs_result=None, go="go", env=None):
    """Execute an original bootstrap phase or verify all its independently compiled receipts."""
    if architecture not in ARCHITECTURES:
        raise ValueError("Standalone source completion requires the original Windows architecture")
    phases = NATIVE.NODE.BOOTSTRAP_SOURCE_PHASES
    if directory is None:
        if (phase not in phases or destination is None or needs_result is not None or
                destination.name != source_filename(architecture, phase) or destination.exists() or destination.is_symlink()):
            raise ValueError("Standalone source phase requires a new original receipt path")
    elif (phase is not None or destination is not None or needs_result != "success" or directory.is_symlink() or
          not directory.is_dir() or {p.name for p in directory.iterdir()} != {source_filename(architecture, p) for p in phases}):
        raise ValueError("Standalone source completion requires every successful phase and its exact receipt")

    expected = context(os.environ if env is None else env)
    verify_checkout(expected)
    completed = []

    def selected(source, compiler, *, prospective, env, bootstrap_only):
        if not bootstrap_only or prospective or env.get("GOARCH") != architecture:
            raise ValueError("Standalone source evidence requires the exact native bootstrap owner")
        source, before = NATIVE.NODE.checked_sources(source)
        original = comparable_source(source, before, compiler, env)
        names, images = NATIVE.NODE.source_phase_inventory(source, bootstrap_only=True)
        if directory is None:
            native = NATIVE.NODE.execute(source, compiler, bootstrap_only=True, env=env, phase=phase)
            NATIVE.NODE.validate_source_phase(native, phase, NATIVE.NODE.source_records_digest(before), architecture, names, images)
            completed.append({"format": SOURCE_FORMAT, **expected, "native": native, "comparable_source_sha256": original,
                              "original_module_sha256": before["go.mod"]})
        else:
            for required in phases:
                value = read_receipt(directory / source_filename(architecture, required))
                native = validate_context(value, expected, SOURCE_FORMAT)
                if value["comparable_source_sha256"] != original:
                    raise ValueError("Standalone source receipts differ from the newly prepared original source")
                # Only the verified absolute sibling Xray path can differ
                # between these newly prepared cores. Rebuild the producer's
                # exact raw digest using its original verified module bytes.
                module = value["original_module_sha256"]
                if not isinstance(module, str) or not re.fullmatch(r"[0-9a-f]{64}", module):
                    raise ValueError("Standalone source receipt lost its original module digest")
                raw = NATIVE.NODE.source_records_digest(dict(before, **{"go.mod": module}))
                NATIVE.NODE.validate_source_phase(native, required, raw, architecture, names, images)
                completed.append(value)
        if NATIVE.NODE.checked_sources(source)[1] != before or comparable_source(source, before, compiler, env) != original:
            raise ValueError("Standalone source or Xray dependency changed during the native gate")

    NATIVE.BOOT.standalone(go, native_test=selected)
    if len(completed) != (len(phases) if directory is not None else 1):
        raise ValueError("Standalone preparation failed to complete its exact source inventory")
    verify_checkout(expected)
    if destination is not None:
        with destination.open("x", encoding="utf-8") as stream:
            json.dump(completed[0], stream, sort_keys=True)
            stream.write("\n")
    print(f"Windows {architecture} standalone source verified for {expected['commit']}: " +
          ", ".join(value["native"]["phase"] for value in completed), flush=True)
    return completed


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=NATIVE.PHASES)
    parser.add_argument("--architecture", choices=ARCHITECTURES)
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--go", default="go")
    parser.add_argument("--aggregate", type=Path)
    parser.add_argument("--needs-result")
    parser.add_argument("--source-phase", choices=NATIVE.NODE.BOOTSTRAP_SOURCE_PHASES)
    parser.add_argument("--source-aggregate", type=Path)
    args = parser.parse_args()
    if args.source_phase is not None or args.source_aggregate is not None:
        if args.phase is not None or args.aggregate is not None:
            parser.error("standalone source and WFP kernel receipts use different native gates")
        standalone_source(args.architecture, phase=args.source_phase, destination=args.receipt,
                          directory=args.source_aggregate, needs_result=args.needs_result, go=args.go)
    elif args.aggregate is not None:
        if any(value is not None for value in (args.phase, args.architecture, args.receipt)) or args.needs_result is None:
            parser.error("aggregation requires its matrix result and no individual phase")
        aggregate(args.aggregate, args.needs_result)
    else:
        if any(value is None for value in (args.phase, args.architecture, args.receipt)) or args.needs_result is not None:
            parser.error("native execution requires architecture, phase and new receipt path")
        run_phase(args.architecture, args.phase, args.receipt, args.go)
