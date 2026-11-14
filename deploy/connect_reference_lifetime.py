#!/usr/bin/env python3
"""Original established CONNECT reference lifetime and its restored-deadline control."""
import hashlib
import json
import re

ROOT = "TestRouterVPNCONNECTReferenceEstablishedLifetime"
CASES = ("retained", "handshake-refused", "established-refused")
NAMES = (ROOT, *(ROOT + "/" + case for case in CASES))
CONTROL = dict(name="reference-established-deadline", path="protocol/routervpnamnezia/desktop_reference_test.go",
    before="\t\t\t\t\tresult = errors.Join(c.SetDeadline(time.Time{}), peer.SetDeadline(time.Time{}))\n",
    after="", witness="original established CONNECT stream expired")

def control_events(raw, status):
    output = raw.decode()
    names = (ROOT, ROOT + "/retained")
    runs = re.findall(r"(?m)^=== RUN\s+(\S+)\s*$", output)
    failed = re.findall(r"(?m)^\s*--- FAIL: (\S+) \([^\n]*\)$", output)
    if (status != 1 or sorted(runs) != sorted(names) or sorted(failed) != sorted(names)
        or output.count(CONTROL["witness"]) != 1
        or any(value in output for value in ("DATA RACE", "panic:", "--- SKIP:", "--- PASS:", "[build failed]"))):
        raise ValueError("Original established CONNECT deadline control failed")
    return dict(expected_failure=True, witness=CONTROL["witness"], failed=failed)

def validate(base, gate, run, compiler, owner, peer, work, flags):
    identity = base.COMMON.image_identity(peer)
    status, raw = run("reference-established-positive", [peer, "-test.run=^" + ROOT + "$",
        "-test.count=1", "-test.timeout=45s", "-test.v"], owner, 60)
    if status:
        raise ValueError("Original established CONNECT reference lifetime failed")
    gate.NODE.require_native_verdicts(raw.decode(), NAMES, "original established CONNECT reference lifetime")
    original = owner / CONTROL["path"]
    changed = base.mutate(CONTROL, original.read_text())
    replacement = work / (CONTROL["name"] + ".go")
    replacement.write_text(changed)
    mapping = work / (CONTROL["name"] + ".json")
    mapping.write_text(json.dumps({"Replace": {str(original): str(replacement)}}))
    status, raw = run(CONTROL["name"], [compiler, "test", *flags, "-overlay=" + str(mapping),
        "-run=^" + ROOT + "$/^retained$", "-count=1", "-timeout=45s", "-v", "./protocol/routervpnamnezia"], owner, 600)
    negative = control_events(raw, status)
    if base.COMMON.image_identity(peer) != identity:
        raise ValueError("Original established CONNECT peer image changed")
    return dict(reference_established_records=list(NAMES), reference_established_control=dict(
        original_sha256=hashlib.sha256(original.read_bytes()).hexdigest(),
        mutation_sha256=hashlib.sha256(changed.encode()).hexdigest(), **negative),
        reference_established_scope="original >30-second TCP stream and owners; unchanged bounded handshake refusal, context and one-second reciprocal-close watchdog")
