#!/usr/bin/env python3
"""Execute the complete Windows Node baseline in independently bounded native jobs."""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import stat

import test_windows_node_process as gate
from test_windows_node_physical_ci import context, verify_checkout


GROUPS = ("native-early-shared", "late-shared", "ordered", "latency", "product")
IMAGE = "node-process.test.exe"
VERSION = "go1.26.3"
TARGET = "windows/amd64"
IMAGE_LIMIT = 512 << 20
LOG_LIMIT = 64 << 20
JSON_LIMIT = 64 << 10
HEADER = "=== ROUTERVPN WINDOWS NODE BASELINE "
FLAGS = ("-c", "-mod=readonly", "-gcflags=all=-d=checkptr=2", "-tags=" + gate.TAG, "-race")
SCHEMA = "routervpn-windows-node-process-baseline-v1"


def partition():
    buckets = {name: [] for name in GROUPS}
    all_groups = gate.baseline_groups()
    for label, selected, expected in all_groups:
        if label == "native-child-and-storage":
            name = "native-early-shared"
        elif match := re.fullmatch(r"shared-ownership-([1-9][0-9]*)", label):
            name = "native-early-shared" if int(match[1]) <= 6 else "late-shared"
        elif label.startswith("ordered-Test"):
            name = "ordered"
        elif label.startswith(("imported-latency-Test", "selected-latency-Test")):
            name = "latency"
        elif label.startswith(("product-Test", "single-node-off-Test")):
            name = "product"
        else:
            raise ValueError("Unassigned original Windows Node baseline group: " + label)
        buckets[name].append((label, selected, expected))
    if any(not value for value in buckets.values()) or tuple(g for b in buckets.values() for g in b) != all_groups:
        raise ValueError("Windows Node baseline partition changed its original inventory or order")
    return buckets


def exact_directory(directory, names):
    if (not directory.is_dir() or directory.is_symlink() or
            getattr(directory.lstat(), "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT or
            {p.name for p in directory.iterdir()} != set(names)):
        raise ValueError("Incomplete or foreign Windows Node artifact inventory")


def read_file(path, limit, *, collect=False):
    def identity(info):
        if (not stat.S_ISREG(info.st_mode) or not info.st_ino or info.st_nlink != 1 or
                getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT or
                not 0 < info.st_size <= limit):
            raise ValueError("Windows Node receipt or image is not an original bounded regular file")
        return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns

    before = identity(path.lstat())
    with path.open("rb") as stream:
        if identity(os.fstat(stream.fileno())) != before:
            raise ValueError("Windows Node artifact changed before readback")
        if collect:
            data = stream.read(before[2] + 1)
            if len(data) != before[2]:
                raise ValueError("Windows Node artifact changed length during readback")
            digest = hashlib.sha256(data).hexdigest()
        else:
            data = None
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        if identity(os.fstat(stream.fileno())) != before:
            raise ValueError("Windows Node artifact changed during readback")
    if identity(path.lstat()) != before:
        raise ValueError("Windows Node artifact was replaced after readback")
    return before, digest, data


def load_json(path):
    def unique(items):
        result = dict(items)
        if len(result) != len(items):
            raise ValueError("Duplicate Windows Node receipt field")
        return result
    return json.loads(read_file(path, JSON_LIMIT, collect=True)[2], object_pairs_hook=unique)


def write_json(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, sort_keys=True)
        stream.write("\n")


def source_snapshot(scope):
    verify_checkout(scope)
    return hashlib.sha256(json.dumps(gate.sources(), sort_keys=True).encode()).hexdigest()


def public_scope(scope, source):
    return {"schema": SCHEMA, "repository": scope["repository"], "commit": scope["commit"], "run_id": scope["run_id"],
            "target": TARGET, "toolchain": VERSION, "source_sha256": source}


def valid_attempt(value, scope):
    return (isinstance(value, str) and re.fullmatch(r"[1-9][0-9]{0,19}", value) is not None
            and int(value) <= int(scope["run_attempt"]))


def original_compiler(go, environment):
    compiler, captured, architecture, build = gate.native_compilation(go, environment)
    if architecture != "amd64" or tuple(build[2:]) != FLAGS or captured["CGO_ENABLED"] != "1":
        raise ValueError("Windows Node baseline requires the original native AMD64 race compiler and flags")
    return compiler, captured, build


def verify_build_info(compiler, image, captured):
    code, output = gate.NATIVE.run([compiler, "version", "-m", image], cwd=gate.ROOT, env=captured, timeout=30)
    lines = output.splitlines()
    required = ("\tpath\trouter-vpn/cmd/client.test", "\tbuild\t-buildmode=exe", "\tbuild\t-compiler=gc",
                "\tbuild\t-gcflags=all=-d=checkptr=2", "\tbuild\t-race=true", "\tbuild\t-tags=" + gate.TAG,
                "\tbuild\tGOOS=windows", "\tbuild\tGOARCH=amd64", "\tbuild\tCGO_ENABLED=1")
    if code or not lines or lines[0] != str(image) + ": " + VERSION or any(lines.count(v) != 1 for v in required):
        raise ValueError("Windows Node executable does not carry its original target, package or build flags")


def image_manifest(scope, source, attempt, digest, size):
    return {**public_scope(scope, source), "producer_attempt": attempt, "sha256": digest, "bytes": size}


def adopt(directory, scope, source):
    exact_directory(directory, (IMAGE, "image.json"))
    value = load_json(directory / "image.json")
    image = (directory / IMAGE).absolute()
    identity, digest, _ = read_file(image, IMAGE_LIMIT)
    attempt = value.get("producer_attempt") if isinstance(value, dict) else None
    if not valid_attempt(attempt, scope) or value != image_manifest(scope, source, attempt, digest, identity[2]):
        raise ValueError("Windows Node executable belongs to another source, compiler, run or producer")
    return image, identity, value


def prepare_image(out, scope, go, environment):
    source = source_snapshot(scope)
    compiler, captured, build = original_compiler(go, environment)
    out.mkdir(mode=0o700)
    image = (out / IMAGE).absolute()
    compiled = gate.compile_baseline(image, build, captured)
    identity, digest, _ = read_file(image, IMAGE_LIMIT)
    if digest != compiled:
        raise ValueError("Original Windows Node executable changed after compilation")
    verify_build_info(compiler, image, captured)
    if read_file(image, IMAGE_LIMIT)[:2] != (identity, digest) or source_snapshot(scope) != source:
        raise ValueError("Original Windows Node build source or executable changed before publication")
    write_json(out / "image.json", image_manifest(scope, source, scope["run_attempt"], digest, identity[2]))


def verify_transcript(raw, groups):
    output = raw.decode("utf-8")
    sections = []
    for line in output.splitlines(keepends=True):
        if line.startswith(HEADER):
            sections.append((line.removeprefix(HEADER).rstrip("\r\n"), []))
        elif sections:
            sections[-1][1].append(line)
        else:
            raise ValueError("Windows Node transcript precedes its first original group")
    if [label for label, _ in sections] != [label for label, _, _ in groups]:
        raise ValueError("Windows Node transcript lost or duplicated original baseline groups")
    all_outputs = []
    for (_, rows), (_, selected, expected) in zip(sections, groups):
        body = "".join(rows)
        lines = body.splitlines()
        runs = Counter(line.removeprefix("=== RUN   ") for line in lines if line.startswith("=== RUN   "))
        if (not lines or lines[-1] != "PASS" or lines.count("PASS") != 1 or
                any(runs[name] != 1 for name in expected) or any(n.split("/", 1)[0] not in selected for n in runs)):
            raise ValueError("Windows Node transcript did not run its original roots and leaves to completion")
        gate.check_baseline(0, body, expected)
        all_outputs.append(body)
    return "\n".join(all_outputs)


def phase_record(original, attempt, group, raw, selected):
    return {"image": original, "run_attempt": attempt, "group": group, "log_sha256": hashlib.sha256(raw).hexdigest(),
            "groups": [label for label, _, _ in selected],
            "roots": sum(len(roots) for _, roots, _ in selected), "verdicts": sum(len(names) for _, _, names in selected)}


def run_group(name, directory, out, scope, go, environment):
    selected = partition()[name]
    source = source_snapshot(scope)
    compiler, captured, _ = original_compiler(go, environment)
    image, identity, original = adopt(directory, scope, source)
    verify_build_info(compiler, image, captured)
    if read_file(image, IMAGE_LIMIT)[:2] != (identity, original["sha256"]):
        raise ValueError("Original Windows Node executable changed before native execution")
    outputs = gate.execute_baseline(image, captured, original["sha256"], groups=selected)
    raw = "".join(HEADER + label + "\n" + output
                  for (label, _, _), output in zip(selected, outputs, strict=True)).encode("utf-8")
    if len(raw) > LOG_LIMIT:
        raise ValueError("Windows Node group exceeded its transcript bound")
    verify_transcript(raw, selected)
    if adopt(directory, scope, source) != (image, identity, original) or source_snapshot(scope) != source:
        raise ValueError("Original Windows Node executable or source changed during native execution")
    out.mkdir(mode=0o700)
    with (out / "native.log").open("xb") as log:
        log.write(raw)
    write_json(out / "phase.json", phase_record(original, scope["run_attempt"], name, raw, selected))


def aggregate(directory, receipts, out, scope, jobs):
    if (not isinstance(jobs, dict) or set(jobs) != {"image", "baseline", "controls"} or
            any(not isinstance(job, dict) or job.get("result") != "success" for job in jobs.values())):
        raise ValueError("Windows Node acceptance requires the original image, every baseline shard and all control suites")
    source = source_snapshot(scope)
    image, identity, original = adopt(directory, scope, source)
    names = {name: f"windows-node-process-baseline-{name}-{scope['commit']}-{scope['run_id']}" for name in GROUPS}
    exact_directory(receipts, names.values())
    transcripts, records = [], []
    for name, selected in partition().items():
        path = receipts / names[name]
        exact_directory(path, ("phase.json", "native.log"))
        value, raw = load_json(path / "phase.json"), read_file(path / "native.log", LOG_LIMIT, collect=True)[2]
        attempt = value.get("run_attempt") if isinstance(value, dict) else None
        if (not valid_attempt(attempt, scope) or int(attempt) < int(original["producer_attempt"]) or
                value != phase_record(original, attempt, name, raw, selected)):
            raise ValueError("Windows Node phase receipt does not match its original run, image or transcript")
        transcripts.append(verify_transcript(raw, selected))
        records.append(value)
    gate.check_baseline(0, "\n".join(transcripts))
    if source_snapshot(scope) != source or adopt(directory, scope, source) != (image, identity, original):
        raise ValueError("Windows Node acceptance changed its original source or executable")
    out.mkdir(mode=0o700)
    write_json(out / "accepted.json", {"image": original, "run_attempt": scope["run_attempt"], "phases": records,
               "roots": len(gate.REQUIRED), "verdicts": len(gate.EXPECTED), "groups": len(gate.baseline_groups())})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("image", "run", "aggregate"):
        command = commands.add_parser(name)
        command.add_argument("--output", type=Path, required=True)
        if name != "image":
            command.add_argument("--image", required=True, type=Path)
        if name != "aggregate":
            command.add_argument("--go", default="go")
        if name == "run":
            command.add_argument("--group", choices=GROUPS, required=True)
        if name == "aggregate":
            command.add_argument("--receipts", required=True, type=Path)
    args = parser.parse_args()
    scope = context(os.environ)
    if args.command == "image":
        prepare_image(args.output, scope, args.go, os.environ)
    elif args.command == "run":
        run_group(args.group, args.image, args.output, scope, args.go, os.environ)
    else:
        aggregate(args.image, args.receipts, args.output, scope, json.loads(os.environ["NATIVE_REQUIRED_JOBS"]))


if __name__ == "__main__":
    main()
