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
        if "_ = a.persistProfilesLocked()" in line:
            ignored.append((path.name, idx + 1, line.strip()))
            errors.append(f"{path.name}:{idx + 1}: ignored persistProfilesLocked result")
        if re.search(r"\b_\s*=\s*a\.persistProfiles\(\)", line):
            errors.append(f"{path.name}:{idx + 1}: ignored persistProfiles result")

if ignored:
    rendered = ", ".join(f"{name}:{line}" for name, line, _ in ignored)
    errors.append(f"profile persistence failures must never be ignored: {rendered}")

main_body = (CLIENT / "main.go").read_text(encoding="utf-8", errors="replace")
usage_body = (CLIENT / "usage_metadata.go").read_text(encoding="utf-8", errors="replace")
if "recordProfileUsageLocked" not in main_body or 'log.Printf("profile usage metadata was not persisted:' not in main_body:
    errors.append("main.go no longer handles bounded post-connect usage metadata persistence errors")
for marker in ("previous := a.profiles.Profiles[i]", "a.profiles.Profiles[i] = previous", "persistProfilesLocked()"):
    if marker not in usage_body:
        errors.append(f"usage_metadata.go missing rollback/persistence marker {marker!r}")

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
print("Router VPN profile persistence error audit: PASS (zero ignored profile persistence failures)")
