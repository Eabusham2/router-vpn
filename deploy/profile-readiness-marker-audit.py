#!/usr/bin/env python3
"""Keep profile-engine readiness markers derived from complete verified private state."""
from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
errors: list[str] = []


def read(rel: str) -> str:
    path = ROOT / rel
    if not path.is_file():
        errors.append(f"missing profile-readiness source: {rel}")
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def need(rel: str, *markers: str) -> str:
    body = read(rel)
    for marker in markers:
        if marker not in body:
            errors.append(f"{rel}: missing readiness marker {marker!r}")
    return body


ensure = need(
    "server/finalize/ensure-profile-engines.sh",
    "PRIVATE_DIR=/src/server/scripts/private-directory.py",
    "PRIVATE_WRITE=/src/server/scripts/atomic-private-write.py",
    "PRIVATE_BATCH=/src/server/scripts/atomic-private-batch.py",
    "VERIFIED_READ=/src/server/scripts/verified-regular-read.py",
    'private_ok(){',
    'marker_ok(){',
    'write_marker(){',
    'clear_marker(){',
    'verified_json_tags(){',
    'advanced_credentials_ready(){',
    'advanced_runtime_ready(){',
    'private_ok "$GENERATED/reality-xhttp/sing-box.json"',
    "grep -q '^CHAIN_READY=1$'",
    "grep -q '^PQ_BASE=1$'",
    'private_ok "$GENERATED/$d/rosenpass-client-secret"',
    "Marker files are derived readiness attestations only.",
    "preserving the prior transactional generation",
    """write_marker "$CORE_MARKER" 'core-transports-xray-v2'""",
    """write_marker "$ADV_MARKER" 'advanced-profiles-v2'""",
    """write_marker "$TLS_MARKER" 'tls-alternates-v1'""",
)
for forbidden in (
    'printf \'%s\\n\' \'core-transports-xray-v2\' >"$CORE_MARKER"',
    'printf \'%s\\n\' \'advanced-profiles-v2\' >"$ADV_MARKER"',
    'printf \'%s\\n\' \'tls-alternates-v1\' >"$TLS_MARKER"',
    'chmod 600 "$CORE_MARKER"',
    'chmod 600 "$ADV_MARKER"',
    'chmod 600 "$TLS_MARKER"',
    '[[ ! -s "$CORE_MARKER" ]]',
    '[[ ! -s "$ADV_MARKER" ]]',
    '[[ ! -s "$TLS_MARKER" ]]',
    "sed -i 's/^PQ_BASE=",
    "echo 'PQ_BASE=0' >>",
    'rm -rf "$GENERATED/split" "$GENERATED/max"',
):
    if forbidden in ensure:
        errors.append(f"ensure-profile-engines.sh contains stale readiness mutation {forbidden!r}")

# The advanced marker must be written only in the branch that re-proves the
# complete runtime after both refresh attempts, never immediately after raw
# credential generation.
adv_runtime = ensure.find("if advanced_runtime_ready; then")
adv_marker = ensure.find("""write_marker "$ADV_MARKER" 'advanced-profiles-v2'""")
raw_generation = ensure.find("generate-advanced-profiles.sh")
if min(adv_runtime, adv_marker, raw_generation) < 0 or not (raw_generation < adv_runtime < adv_marker):
    errors.append("advanced readiness marker is not ordered after complete runtime proof")

adopt = need(
    "server/finalize/adopt-current-markers.sh",
    "PRIVATE_DIR=/src/server/scripts/private-directory.py",
    "PRIVATE_WRITE=/src/server/scripts/atomic-private-write.py",
    "PRIVATE_BATCH=/src/server/scripts/atomic-private-batch.py",
    "VERIFIED_READ=/src/server/scripts/verified-regular-read.py",
    "verified_json_tags(){",
    "advanced_current(){",
    '"$GEN/reality-xhttp/xray.json" "$GEN/reality-xhttp/sing-box.json"',
    "grep -q '^CHAIN_READY=1$'",
    "grep -q '^PQ_BASE=1$'",
    'private_ok "$GEN/$d/rosenpass-client-secret"',
    "Existing state is the source of truth.",
    """write_marker "$CORE_MARKER" 'core-transports-xray-v2'""",
    """write_marker "$ADV_MARKER" 'advanced-profiles-v2'""",
    """write_marker "$TLS_MARKER" 'tls-alternates-v1'""",
    'clear_marker "$CORE_MARKER"',
    'clear_marker "$ADV_MARKER"',
    'clear_marker "$TLS_MARKER"',
)
for forbidden in (
    '>"$CONFIG/.core-transports-xray-v2"',
    '>"$CONFIG/.advanced-profiles-v2"',
    '>"$CONFIG/.tls-alternates-v1"',
    '[[ ! -s "$CONFIG/.core-transports-xray-v2" ]]',
    '[[ ! -s "$CONFIG/.advanced-profiles-v2" ]]',
    '[[ ! -s "$CONFIG/.tls-alternates-v1" ]]',
):
    if forbidden in adopt:
        errors.append(f"adopt-current-markers.sh contains stale marker shortcut {forbidden!r}")

doctor = need(
    "server/scripts/doctor-current.sh",
    'verified_private_text(){',
    "$BASE/config/.core-transports-xray-v2|core-transports-xray-v2",
    "$BASE/config/.advanced-profiles-v2|advanced-profiles-v2",
    "$BASE/config/.tls-alternates-v1|tls-alternates-v1",
    '[[ "$value" == "$expected" ]]',
    "profile marker missing/unsafe/stale",
)
if '[[ -s "$marker" ]]' in doctor:
    errors.append("doctor-current.sh still trusts readiness marker existence/size")

if errors:
    print("Profile readiness marker audit: FAIL", file=sys.stderr)
    for error in errors:
        print(" -", error, file=sys.stderr)
    raise SystemExit(1)

print("Profile readiness marker audit: PASS")
