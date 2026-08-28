#!/usr/bin/env python3
"""Protect the production install/upgrade environment as private authoritative state."""
from __future__ import annotations

from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
errors: list[str] = []


def read(rel: str) -> str:
    path = ROOT / rel
    if not path.is_file():
        errors.append(f"missing production install source: {rel}")
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


install = read("server/install.sh")
for marker in (
    'PRIVATE_WRITE="$ROOT_DIR/server/scripts/atomic-private-write.py"',
    'python3 "$PRIVATE_WRITE" "$ENV_FILE" <<ENV',
    'ROUTER_VPN_PRODUCTION_COMPOSE must point to a generated exact-SHA production compose',
    'verify-production-compose.py" "$COMPOSE"',
):
    if marker not in install:
        errors.append(f"server/install.sh missing private/exact-release marker {marker!r}")
for forbidden in (
    'cat >"$ENV_FILE"',
    'chmod 600 "$ENV_FILE"',
    'server/portainer-current.yaml',
):
    if forbidden in install:
        errors.append(f"server/install.sh contains stale unsafe marker {forbidden!r}")


init = read("server/init/noninteractive.sh")
for marker in (
    "VERIFIED_READ=/src/server/scripts/verified-regular-read.py",
    '[[ -e "$BASE/.initialized" || -L "$BASE/.initialized" ]]',
    'python3 "$VERIFIED_READ" --private "$BASE/.initialized"',
    "refusing credential regeneration",
    'printf \'initialized\\n\' | python3 "$PRIVATE_WRITE" "$BASE/.initialized"',
):
    if marker not in init:
        errors.append(f"server/init/noninteractive.sh missing initialization-state marker {marker!r}")
apply_pos = init.rfind('/src/server/scripts/apply-runtime.sh "$WAN_INTERFACE" "$LAN_CIDR"')
marker_pos = init.rfind('printf \'initialized\\n\' | python3 "$PRIVATE_WRITE" "$BASE/.initialized"')
if apply_pos < 0 or marker_pos < 0 or apply_pos > marker_pos:
    errors.append("initialization marker is not published strictly after successful runtime application")

upgrade = read("server/upgrade.sh")
for marker in (
    'VERIFIED_READ="$ROOT_DIR/server/scripts/verified-regular-read.py"',
    'python3 "$VERIFIED_READ" --private "$ENV_FILE" >/dev/null',
    'python3 "$VERIFIED_READ" --private "$INIT_MARKER"',
    '[[ "$marker" == initialized ]]',
    'verify-production-compose.py" "$COMPOSE"',
    'docker compose --env-file "$ENV_FILE" -f "$COMPOSE"',
):
    if marker not in upgrade:
        errors.append(f"server/upgrade.sh missing verified-state marker {marker!r}")
for forbidden in (
    '[[ -s "$ENV_FILE" ]]',
    'server/portainer-current.yaml',
):
    if forbidden in upgrade:
        errors.append(f"server/upgrade.sh contains stale unsafe marker {forbidden!r}")

reader = read("server/scripts/verified-regular-read.py")
for marker in (
    'argv[1] == "--private"',
    'stat.S_IMODE(before.st_mode) != 0o600',
    'stat.S_IMODE(opened.st_mode) != 0o600',
    'stat.S_IMODE(current.st_mode) != 0o600',
    'os.O_NOFOLLOW',
):
    if marker not in reader:
        errors.append(f"verified-regular-read.py missing private read marker {marker!r}")

if not errors:
    proc = subprocess.run(
        [sys.executable, str(ROOT / "server/scripts/test_verified_regular_read.py")],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if proc.returncode != 0:
        errors.append("verified regular/private reader tests failed: " + (proc.stdout + proc.stderr)[-4000:])

if errors:
    print("Production install state audit: FAIL", file=sys.stderr)
    for error in errors:
        print(" -", error, file=sys.stderr)
    raise SystemExit(1)

print("Production install state audit: PASS")
