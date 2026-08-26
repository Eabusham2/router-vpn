#!/usr/bin/env python3
"""Reject silently ignored durable client-profile persistence failures."""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLIENT = ROOT / "cmd" / "client"
errors: list[str] = []
ignored: list[tuple[str, int, str]] = []

for path in sorted(CLIENT.glob("*.go")):
    if path.name.endswith("_test.go"):
        continue
    body = path.read_text(encoding="utf-8", errors="replace")
    lines = body.splitlines()
    for idx, line in enumerate(lines):
        if "_ = a.persistProfilesLocked()" not in line:
            continue
        start = max(0, idx - 12)
        end = min(len(lines), idx + 4)
        context = "\n".join(lines[start:end])
        ignored.append((path.name, idx + 1, context))
        # One legacy best-effort metadata write is explicitly non-authoritative:
        # after a mode is already path-proved Connected, main.go increments only
        # UseCount/LastUsedAt. A disk failure may lose/revert those ranking hints
        # but must not change connection truth, profile identity, DNS, MTU, exit,
        # selected node, or any security policy. No second ignored call is allowed.
        allowed = (
            path.name == "main.go"
            and "UseCount++" in context
            and "LastUsedAt = time.Now().UTC().Format(time.RFC3339)" in context
            and "a.state.Connected = true" in context
            and "a.state.Phase = \"connected\"" in context
        )
        if not allowed:
            errors.append(f"{path.name}:{idx + 1}: ignored persistProfilesLocked result outside non-authoritative usage metadata")

    # Whole-store persistence must never be discarded either.
    for idx, line in enumerate(lines):
        if re.search(r"\b_\s*=\s*a\.persistProfiles\(\)", line):
            errors.append(f"{path.name}:{idx + 1}: ignored persistProfiles result")

if len(ignored) != 1:
    rendered = ", ".join(f"{name}:{line}" for name, line, _ in ignored) or "none"
    errors.append(f"expected exactly one classified best-effort usage-metadata persistence call, found {len(ignored)}: {rendered}")

# Critical mutation families must continue to carry explicit rollback markers.
critical = {
    "main.go": ("rollbackProfilesLocked", "previousProfiles", "oldStore"),
    "dns_policy_api.go": ("oldProfile", "persistProfilesLocked"),
    "home_summary.go": ("previousStore", "rollbackProfilesLocked"),
    "extras.go": ("previousStore", "rollbackProfilesLocked"),
    "telemetry.go": ("previousStore", "rollbackProfilesLocked"),
    "mtu_retest.go": ("previous := *x", "*x = previous"),
    "connection_profiles.go": ("rollbackProfilesLocked", "persistProfilesLocked"),
}
for name, markers in critical.items():
    path = CLIENT / name
    if not path.is_file():
        errors.append(f"missing critical profile persistence source {name}")
        continue
    body = path.read_text(encoding="utf-8", errors="replace")
    for marker in markers:
        if marker not in body:
            errors.append(f"{name}: missing profile-persistence rollback marker {marker!r}")

if errors:
    for error in errors:
        print("ERROR:", error)
    raise SystemExit(1)
print("Router VPN profile persistence error audit: PASS (only post-connect usage ranking metadata is best-effort)")
