#!/usr/bin/env python3
"""Reject silently ignored durable client-profile persistence failures."""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLIENT = ROOT / "cmd" / "client"
errors: list[str] = []
ignored: list[tuple[str, int, str]] = []


def dns_policy_transaction_errors(source: str) -> list[str]:
    """Check the shipping DNS mutation, including its current-object rollback.

    DNS editors capture both the selected private source and its entry. The
    final transaction copies DNS fields into the re-read current profile so
    concurrent display/measurement updates survive both success and rollback.
    These source checks complement the executable failure-injection tests.
    """
    match = re.search(r"func \(a \*app\) dnsPolicy\([^\n]+\) \{.*?\n\}", source, re.S)
    if not match:
        return ["dns_policy_api.go: missing DNS policy transaction"]
    body = re.sub(r"(?m)^\s*//[^\n]*", "", match.group())
    patterns = (
        ("owned settings transaction", r"if r\.Method == http\.MethodPost \{\s*release, err := a\.beginMutationOperation\(r\).*?defer release\(\)"),
        ("captured selected source and entry", r"a\.mu\.Lock\(\)\s*profile, entry, ok := a\.dnsPolicySelectionLocked\(\)\s*a\.mu\.Unlock\(\).*?token := dnsPolicySelectionToken\(profile, entry\)"),
        ("external revision validation", r"if externalDNSProfile\(profile\) \|\| request\.ProfileID != \"\" \|\| request\.ProfileToken != \"\" \{\s*if request\.ProfileID != profile\.ID \|\| request\.ProfileToken == \"\" \|\| request\.ProfileToken != token \{.*?http\.StatusConflict\)\s*return"),
        ("current source and idle recheck", r"a\.mu\.Lock\(\)\s*current, currentEntry, exists := a\.dnsPolicySelectionLocked\(\)\s*if !exists \|\| current\.ID != profile\.ID \|\| dnsPolicySelectionToken\(current, currentEntry\) != token \|\|\s*a\.closing \|\| r\.Context\(\)\.Err\(\) != nil \|\| profileSettingsBusy\(a\.state\.Connected, a\.state\.Phase\) \{\s*a\.mu\.Unlock\(\)\s*http\.Error\(w, [^\n]*http\.StatusConflict\)\s*return\s*\}"),
        ("DNS-only update of current profile", r"currentUpdate := cloneRouterProfile\(current\)\s*copyDNSPolicy\(&currentUpdate, updated\)\s*for i := range a\.profiles\.Profiles \{\s*if a\.profiles\.Profiles\[i\]\.ID != current\.ID \{\s*continue\s*\}"),
        ("checked persistence and exact rollback", r"a\.profiles\.Profiles\[i\] = currentUpdate\s*err = a\.persistProfilesLocked\(\)\s*if err != nil \{\s*a\.profiles\.Profiles\[i\] = current\s*\}\s*break"),
        ("save failure response before success", r"a\.mu\.Unlock\(\)\s*if err != nil \{\s*http\.Error\(w, [^\n]*http\.StatusInternalServerError\)\s*return\s*\}\s*cancelPendingStartupPolicy\(a\)\s*writeDNSPolicy\(w, currentUpdate, currentEntry\)"),
    )
    return [f"dns_policy_api.go: missing transactional DNS guarantee: {name}"
            for name, pattern in patterns if not re.search(pattern, body, re.S)]


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

dns_path = CLIENT / "dns_policy_api.go"
if dns_path.is_file():
    errors.extend(dns_policy_transaction_errors(dns_path.read_text(encoding="utf-8", errors="replace")))
else:
    errors.append("missing critical profile persistence source dns_policy_api.go")

if errors:
    for error in errors:
        print("ERROR:", error)
    raise SystemExit(1)
print("Router VPN profile persistence error audit: PASS (zero ignored profile persistence failures)")
