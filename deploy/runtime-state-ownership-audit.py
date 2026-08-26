#!/usr/bin/env python3
"""Lock daily-use runtime helpers out of controller-owned persistent profile state."""
from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
errors: list[str] = []


def read(rel: str) -> str:
    path = ROOT / rel
    if not path.is_file():
        errors.append(f"missing runtime ownership source: {rel}")
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def require(rel: str, *markers: str) -> str:
    body = read(rel)
    for marker in markers:
        if marker not in body:
            errors.append(f"{rel}: missing ownership marker {marker!r}")
    return body


def forbid(rel: str, *markers: str) -> None:
    body = read(rel)
    for marker in markers:
        if marker in body:
            errors.append(f"{rel}: forbidden persistent-state ownership marker {marker!r}")


def python_write_calls(rel: str) -> list[tuple[int, str]]:
    body = read(rel)
    try:
        tree = ast.parse(body, filename=rel)
    except SyntaxError as exc:
        errors.append(f"{rel}: cannot parse for ownership audit: {exc}")
        return []
    out: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr not in {"write_text", "write_bytes", "replace", "rename"}:
            continue
        try:
            rendered = ast.unparse(node)
        except Exception:
            rendered = node.func.attr
        out.append((getattr(node, "lineno", 0), rendered))
    return out


# The Go controller is the authoritative daily-use client profile-store owner.
require(
    "cmd/client/main.go",
    "func (a *app) persistProfilesLocked() error",
    "atomicWritePrivate(a.cfg.ProfilesFile",
)
require(
    "cmd/client/private_store.go",
    "validatePrivateParent",
    "os.SameFile(opened, current)",
    "atomicWritePrivate",
)

# DNS policy runtime may read the selected profile and patch only the explicit
# runtime config passed by run-mode. It has no persistence command/API.
dns = require("modes/dns-policy.py", 'ROOT / "routers.json"', "def patch_sing", "patch_sing(Path(sys.argv[2]), s)")
for marker in ("save_profile", "atomicWritePrivate"):
    if marker in dns:
        errors.append(f"modes/dns-policy.py unexpectedly gained persistent-profile logic: {marker}")
for line, call in python_write_calls("modes/dns-policy.py"):
    if "write_text" in call and "path.write_text" not in call:
        errors.append(f"modes/dns-policy.py:{line}: unexpected write outside explicit runtime config: {call}")

# Multihop builder reads linked nodes but may only materialize one disposable
# graph below HOMEVPN_ROOT/run. It must never write routers.json.
require(
    "modes/multihop.py",
    'root / "routers.json"',
    'run_root = (root / "run").resolve()',
    "safe_under(run_root, outdir)",
)
forbid("modes/multihop.py", "routers_path.write", 'root / "routers.json").write', "persistProfiles")

# SMART/CUSTOM orchestration is also read-only with respect to profiles. It may
# stop/start candidate processes, but selected profile policy remains controller-owned.
require(
    "modes/orchestrate.py",
    '(ROOT / "routers.json").read_text()',
    "def selected_profile()",
    "def smart_auto()",
    "def custom()",
)
for line, call in python_write_calls("modes/orchestrate.py"):
    errors.append(f"modes/orchestrate.py:{line}: orchestrator unexpectedly writes filesystem state: {call}")

# ALL reads base preference and owns only a caller-selected runtime result file.
# It never writes routers.json or selected profile policy.
require(
    "modes/run-all.sh",
    '"$ROOT/routers.json"',
    "RESULT_FILE=${HOMEVPN_ALL_RESULT_FILE:-}",
    'mv -f "$tmp" "$RESULT_FILE"',
)
forbid("modes/run-all.sh", '> "$ROOT/routers.json"', 'mv -f "$tmp" "$ROOT/routers.json"')

# MTU startup is explicitly measurement-only. Policy fields are controller-owned;
# normal starts may cache path measurements privately but routers.json is read-only.
require(
    "modes/mtu-policy.py",
    "The Go controller is the sole writer of routers.json/profile policy.",
    'root / "state" / "mtu-auto-cache.json"',
    "measurement-only auto-MTU memory, never routers.json",
    "runtime MTU policy",
)
for line, call in python_write_calls("modes/mtu-policy.py"):
    if "routers.json" in call:
        errors.append(f"modes/mtu-policy.py:{line}: runtime regained routers.json write ownership: {call}")
forbid("modes/mtu-policy.py", 'os.replace(tmp_name, root / "routers.json")', 'path = root / "routers.json"\n    path.parent.mkdir')
require(
    "modes/test_mtu_policy.py",
    "runtime MTU policy mutated controller-owned routers.json",
    "test_symlink_cache_is_never_followed",
    "auto-cache",
)

# The mode launcher reconstructs per-session state under run/. Patching those
# copies is allowed and deliberately excluded from durable profile ownership.
require(
    "modes/run-mode.sh",
    'RUN="$ROOT/run"',
    'CONF="$RUN/profile-$PROFILE_ID-$MODE"',
    'python3 "$SCRIPT_DIR/mtu-policy.py" apply "$CONF"',
    'python3 "$SCRIPT_DIR/dns-policy.py" patch-sing',
)

# Behavioral proof: policy/cache tests assert routers.json byte identity across
# default/manual/auto/Jumbo and cache invalidation cases.
proc = subprocess.run([sys.executable, str(ROOT / "modes/test_mtu_policy.py")], cwd=ROOT, text=True, capture_output=True)
if proc.returncode != 0:
    errors.append("modes/test_mtu_policy.py failed: " + (proc.stdout + "\n" + proc.stderr)[-4000:])

if errors:
    print("Runtime state ownership audit: FAIL", file=sys.stderr)
    for error in errors:
        print(" -", error, file=sys.stderr)
    raise SystemExit(1)

print("Runtime state ownership audit: PASS")
