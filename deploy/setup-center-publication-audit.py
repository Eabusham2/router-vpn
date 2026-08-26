#!/usr/bin/env python3
"""Keep authenticated Setup Center metadata publication private and non-truncating."""
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
errors: list[str] = []


def read(rel: str) -> str:
    path = ROOT / rel
    if not path.is_file():
        errors.append(f"missing Setup Center publication source: {rel}")
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


publish = read("server/scripts/publish-downloads.sh")
for marker in (
    "PRIVATE_DIR=/src/server/scripts/private-directory.py",
    "PRIVATE_WRITE=/src/server/scripts/atomic-private-write.py",
    "PRIVATE_BATCH=/src/server/scripts/atomic-private-batch.py",
    'python3 "$PRIVATE_DIR" "$BUNDLE"',
    'python3 "$PRIVATE_DIR" "$OUT"',
    'mktemp -d "$BUNDLE/.publish-downloads.XXXXXX"',
    'normalize-setup-imports.py "$WORK/normalized"',
    '"$BUNDLE/setup-assets.json=$WORK/normalized/client-bundle/setup-assets.json"',
    '"$BUNDLE/router-vpn-device-setup.html=$WORK/normalized/client-bundle/router-vpn-device-setup.html"',
    "setup-assets.json must remain an object",
    'stage_static "$BUNDLE/router-vpn-device-setup.html" "index.html"',
    'python3 "$PRIVATE_BATCH" "${publish[@]}"',
    "one staged generation",
):
    if marker not in publish:
        errors.append(f"publish-downloads.sh missing atomic-publication marker {marker!r}")
for forbidden in (
    'cp -f "$src" "$OUT/$name"',
    'python3 /src/server/scripts/normalize-setup-imports.py "$BASE"',
    '>"$OUT/SHA256SUMS"',
    'chmod 0600 "$OUT"/*',
    "except Exception:\n    data={}",
):
    if forbidden in publish:
        errors.append(f"publish-downloads.sh contains stale live-write marker {forbidden!r}")

validate_pos = publish.find('python3 "$PRIVATE_DIR" "$OUT"')
purge_pos = publish.find('"$OUT"/router-vpn-client-bundle.zip')
if validate_pos < 0 or purge_pos < 0 or validate_pos > purge_pos:
    errors.append("downloads private-directory validation does not precede legacy private-material purge")

private_dir = read("server/scripts/private-directory.py")
for marker in (
    "validate_existing_ancestors",
    "os.lstat",
    "stat.S_ISLNK",
    "os.makedirs",
    "os.chmod(path, 0o700)",
):
    if marker not in private_dir:
        errors.append(f"private-directory.py missing path-safety marker {marker!r}")

if not errors:
    test = ROOT / "server/scripts/test_private_directory.py"
    proc = subprocess.run([sys.executable, str(test)], cwd=ROOT, text=True, capture_output=True)
    if proc.returncode != 0:
        errors.append("private-directory behavior test failed: " + (proc.stdout + proc.stderr)[-3000:])

if errors:
    print("Router VPN Setup Center publication audit: FAIL", file=sys.stderr)
    for error in errors:
        print(" -", error, file=sys.stderr)
    raise SystemExit(1)
print("Router VPN Setup Center publication audit: PASS")
