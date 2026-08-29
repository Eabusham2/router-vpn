#!/usr/bin/env python3
"""Guard critical GitHub workflow structure against accidental paste/duplication.

This is deliberately a source-structure contract rather than a YAML parser.
The failure class it protects against is a syntactically mangled workflow whose
shell block accidentally contains duplicated workflow steps, preventing Actions
from creating any jobs at all.
"""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def body(rel: str) -> str:
    path = ROOT / rel
    assert path.is_file(), f"missing workflow: {rel}"
    return path.read_text(encoding="utf-8", errors="strict")


aux_rel = ".github/workflows/aux-proxies-ci.yml"
aux = body(aux_rel)

# The healthy workflow is about 15 KiB. Leave generous room for legitimate
# additions while making a 40+ KiB accidental recursive paste impossible to
# merge unnoticed.
assert len(aux.encode("utf-8")) < 25_000, (
    f"{aux_rel}: abnormal size suggests duplicated/embedded workflow content "
    f"({len(aux.encode('utf-8'))} bytes)"
)

critical_steps = (
    "Static checks",
    "Build init ARM64",
    "Run init and finalizer end to end",
    "Verify authenticated generic packages, private bundle, and one-time pairing",
    "Validate formerly grey combined and MAX modes",
    "Build auxiliary proxy ARM64 image",
    "Smoke-test generated OverTLS and SSR services",
)
for name in critical_steps:
    marker = f"      - name: {name}"
    count = aux.count(marker)
    assert count == 1, f"{aux_rel}: expected one {name!r} step, found {count}"

# Step declarations belong only at the workflow indentation. If one appears
# inside a shell body or quoted evidence string, the file was likely pasted
# into itself.
for match in re.finditer(r"(?m)^([ \t]+)- name:[ \t]+(.+)$", aux):
    indent = len(match.group(1))
    assert indent == 6, (
        f"{aux_rel}: embedded/misindented workflow step {match.group(2)!r} "
        f"at indentation {indent}"
    )


# Horizontal indentation only: \\s includes newlines and can count the line
# break before a valid six-space step as a seventh indentation character.
assert re.search(r"(?m)^([ \\t]{6})- name:[ \\t]+Static checks$", aux), (
    f"{aux_rel}: Static checks is not a six-space workflow step"
)

# These are the exact evidence-boundary changes that motivated the last valid
# edit. Keep the fixed pipefail-safe shape while guarding the file structure.
for marker in (
    'unzip -Z1 "$archive" >"$members"',
    'unzip -Z1 "$portable" >"$portable_members"',
    'unzip -Z1 "$bundle" >"$bundle_members"',
    'unzip -p "$bundle" \'*/router-vpn-bundle.json\' >"$bundle_json"',
    'test -z "$(find "$TEST_ROOT/downloads" -maxdepth 1 -type f -name \'*.zip\' -print -quit)"',
):
    assert marker in aux, f"{aux_rel}: missing safe evidence marker {marker!r}"

# Known signatures of the accidental recursive-paste corruption must never
# appear again.
for forbidden in (
    "router-vpn-bundle\\.json          done",
    "grep -q '/router-vpn-bundle.json\n      - name:",
    "grep -q '/generated/wg/wg.conf\n      - name:",
    "grep -q '/generated/max-tls-wg/chain.env\n      - name:",
):
    assert forbidden not in aux, f"{aux_rel}: recursive-paste corruption returned"

# Release-candidate itself must keep exactly one source-audit job and exactly
# one weighted accounting step so a duplicate pasted job cannot falsely amplify
# or bypass evidence.
rc_rel = ".github/workflows/release-candidate.yml"
rc = body(rc_rel)
assert rc.count("  source-audit:") == 1, f"{rc_rel}: source-audit job duplicated/missing"
assert rc.count("      - name: Weighted source/manual release accounting") == 1, (
    f"{rc_rel}: weighted release accounting step duplicated/missing"
)

print("workflow structural integrity audit: OK")
