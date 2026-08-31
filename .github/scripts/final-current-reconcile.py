#!/usr/bin/env python3
from __future__ import annotations
from pathlib import Path
import hashlib, json, re

ROOT = Path(__file__).resolve().parents[2]


def write(rel: str, body: str) -> None:
    p = ROOT / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")

materializer = r'''#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import stat
import tempfile

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
CUSTOM_IMAGES = {
    "init": 3,
    "agent": 1,
    "wireguard": 1,
    "awg2": 1,
    "rosenpass": 1,
    "naive": 1,
    "ss-v2ray": 1,
    "aux": 1,
    "updater": 1,
}
IMAGE_RE = re.compile(
    r"(ghcr\.io/eabusham2/router-vpn-(?:init|agent|wireguard|awg2|rosenpass|naive|ss-v2ray|aux|updater):)"
    r"([0-9a-f]{40})"
)
BROKER_RE = re.compile(r"(?m)^(\s*ROUTER_VPN_GITHUB_SHA:\s*)([0-9a-f]{40})(\s*)$")
MAX_SOURCE_BYTES = 4 << 20
MAX_OUTPUT_BYTES = 8 << 20
PUBLIC_MODE = 0o644


def fail(message: str) -> "NoReturn":
    raise SystemExit(message)


def _parent_snapshot(path: Path) -> os.stat_result:
    info = path.parent.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise RuntimeError(f"refusing unsafe compose parent: {path.parent}")
    return info


def _target_snapshot(path: Path) -> os.stat_result | None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise RuntimeError(f"refusing non-regular/symlink compose target: {path}")
    return info


def _require_target_state(path: Path, expected: os.stat_result | None) -> None:
    try:
        current = path.lstat()
    except FileNotFoundError:
        current = None
    if expected is None:
        if current is not None:
            raise RuntimeError(f"compose target appeared before adoption: {path}")
        return
    if current is None:
        raise RuntimeError(f"compose target disappeared before adoption: {path}")
    if stat.S_ISLNK(current.st_mode) or not stat.S_ISREG(current.st_mode) or not os.path.samestat(expected, current):
        raise RuntimeError(f"compose target identity changed before adoption: {path}")


def read_regular_text(path: Path) -> str:
    path = Path(path)
    parent_before = _parent_snapshot(path)
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise RuntimeError(f"refusing non-regular/symlink compose source: {path}")
    if before.st_size <= 0 or before.st_size > MAX_SOURCE_BYTES:
        raise RuntimeError(f"compose source is empty or oversized: {path}")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(fd)
        current = path.lstat()
        if stat.S_ISLNK(current.st_mode) or not stat.S_ISREG(current.st_mode) or not os.path.samestat(before, opened) or not os.path.samestat(opened, current):
            raise RuntimeError(f"compose source changed during open: {path}")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(64 * 1024, MAX_SOURCE_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_SOURCE_BYTES:
                raise RuntimeError(f"compose source is oversized: {path}")
        parent_after = _parent_snapshot(path)
        current = path.lstat()
        if not os.path.samestat(parent_before, parent_after) or stat.S_ISLNK(current.st_mode) or not stat.S_ISREG(current.st_mode) or not os.path.samestat(opened, current):
            raise RuntimeError(f"compose source changed during read: {path}")
    finally:
        os.close(fd)
    try:
        return b"".join(chunks).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RuntimeError(f"compose source is not UTF-8: {path}") from exc


def validate_template(text: str) -> str:
    if re.search(r"(?m)^\s*build:\s*$", text):
        fail("production template must stay image-only")
    if re.search(r"(?m)^\s*context:\s*https?://", text):
        fail("production template may not use a remote Git build context")
    if re.search(r"(?m)^\s*image:\s*\S+:(?:latest|main|arm64-main)\s*$", text):
        fail("production template may not use floating image tags")
    if "/var/run/docker.sock" in text:
        fail("production template may not grant Docker socket access")
    found: list[str] = []
    for image, expected in CUSTOM_IMAGES.items():
        matches = re.findall(rf"ghcr\.io/eabusham2/router-vpn-{re.escape(image)}:([0-9a-f]{{40}})", text)
        if len(matches) != expected:
            fail(f"expected {expected} exact-SHA template references for router-vpn-{image}, found {len(matches)}")
        found.extend(matches)
    if not found or len(set(found)) != 1:
        fail("production template custom images must share one exact baseline SHA")
    broker = BROKER_RE.search(text)
    if not broker:
        fail("production template broker provenance is not a full SHA")
    if broker.group(2) != found[0]:
        fail("production template broker SHA does not match custom image SHA")
    if "ROUTER_VPN_UPDATE_LISTEN: 127.0.0.1:8793" not in text:
        fail("production template updater must remain loopback-only")
    return found[0]


def materialize(text: str, target_sha: str) -> str:
    target_sha = str(target_sha or "").strip().lower()
    if not SHA_RE.fullmatch(target_sha):
        fail("--sha must be one lowercase 40-character hexadecimal commit SHA")
    baseline = validate_template(text)
    out, image_replacements = IMAGE_RE.subn(lambda match: match.group(1) + target_sha, text)
    out, broker_replacements = BROKER_RE.subn(lambda match: match.group(1) + target_sha + match.group(3), out)
    expected_image_replacements = sum(CUSTOM_IMAGES.values())
    if image_replacements != expected_image_replacements:
        fail(f"expected {expected_image_replacements} custom image replacements, made {image_replacements}")
    if broker_replacements != 1:
        fail(f"expected one broker SHA replacement, made {broker_replacements}")
    if validate_template(out) != target_sha:
        fail("materialized compose does not resolve to the requested exact SHA")
    return (
        f"# GENERATED exact-SHA Router VPN production compose: {target_sha}\n"
        f"# Source template baseline SHA: {baseline}\n"
        "# Generated from server/portainer-current.yaml; do not overwrite the tracked baseline.\n"
        + out
    )


def atomic_write(path: Path, body: str) -> None:
    path = Path(path)
    encoded = body.encode("utf-8")
    if not encoded or len(encoded) > MAX_OUTPUT_BYTES:
        raise RuntimeError(f"materialized compose is empty or oversized: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    parent_before = _parent_snapshot(path)
    target_before = _target_snapshot(path)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.compose-", dir=path.parent)
    tmp = Path(name)
    committed = False
    try:
        os.fchmod(fd, PUBLIC_MODE)
        with os.fdopen(fd, "wb", closefd=True) as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        staged = tmp.lstat()
        if stat.S_ISLNK(staged.st_mode) or not stat.S_ISREG(staged.st_mode) or (os.name != "nt" and stat.S_IMODE(staged.st_mode) != PUBLIC_MODE):
            raise RuntimeError(f"staged compose target is unsafe: {tmp}")
        if not os.path.samestat(parent_before, _parent_snapshot(path)):
            raise RuntimeError(f"compose parent changed before adoption: {path.parent}")
        _require_target_state(path, target_before)
        os.replace(tmp, path)
        committed = True
        current = path.lstat()
        if not os.path.samestat(parent_before, _parent_snapshot(path)) or stat.S_ISLNK(current.st_mode) or not stat.S_ISREG(current.st_mode) or not os.path.samestat(staged, current):
            raise RuntimeError(f"adopted compose target identity changed before verification: {path}")
        try:
            dfd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        except OSError:
            pass
    finally:
        if not committed:
            tmp.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Materialize server/portainer-current.yaml for one exact release commit.")
    parser.add_argument("--sha", required=True)
    parser.add_argument("--input", default="server/portainer-current.yaml", dest="input_path")
    parser.add_argument("--output", required=True, dest="output_path")
    args = parser.parse_args()
    output = Path(args.output_path)
    rendered = materialize(read_regular_text(Path(args.input_path)), args.sha)
    atomic_write(output, rendered)
    print(f"Materialized {output} for exact release SHA {args.sha}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''
write("deploy/materialize-production-compose.py", materializer)

for rel in ("deploy/package-macos-native.sh", "deploy/package-linux-native.sh", "deploy/package-builds.sh"):
    p = ROOT / rel
    if p.exists():
        body = p.read_text(encoding="utf-8").replace("$ROOT/deploy/source_provenance.py", "$ROOT/server/scripts/source_provenance.py")
        body = body.replace('"$ROOT/deploy/source_provenance.py"', '"$ROOT/server/scripts/source_provenance.py"')
        p.write_text(body, encoding="utf-8")

p = ROOT / "server/scripts/build-download-on-demand.py"
if p.exists():
    body = p.read_text(encoding="utf-8")
    body = re.sub(
        r'PROVENANCE_PATH\s*=\s*Path\(__file__\)\.resolve\(\)\.parents\[2\]\s*/\s*"deploy"\s*/\s*"source_provenance\.py"',
        'PROVENANCE_PATH = Path(__file__).with_name("source_provenance.py")', body)
    p.write_text(body, encoding="utf-8")

prov = ROOT / "server/scripts/source_provenance.py"
if prov.exists():
    body = prov.read_text(encoding="utf-8")
    if "source provenance manifest identity changed after adoption" not in body:
        old = "        _safe_existing(path)\n        os.replace(tmp, path)\n        committed = True\n        try:\n"
        new = "        _safe_existing(path)\n        staged = tmp.lstat()\n        os.replace(tmp, path)\n        committed = True\n        current_root = root.lstat()\n        current = path.lstat()\n        if (stat.S_ISLNK(current_root.st_mode) or not stat.S_ISDIR(current_root.st_mode) or not os.path.samestat(root_before, current_root) or stat.S_ISLNK(current.st_mode) or not stat.S_ISREG(current.st_mode) or not os.path.samestat(staged, current)):\n            raise RuntimeError(\"source provenance manifest identity changed after adoption\")\n        try:\n"
        if old in body:
            body = body.replace(old, new, 1)
    if "source provenance manifest changed during read" not in body:
        old = "        body = os.read(fd, MAX_MANIFEST + 1)\n    finally:\n        os.close(fd)\n"
        new = "        body = os.read(fd, MAX_MANIFEST + 1)\n        current = path.lstat()\n        if stat.S_ISLNK(current.st_mode) or not stat.S_ISREG(current.st_mode) or not os.path.samestat(opened, current):\n            raise RuntimeError(\"source provenance manifest changed during read\")\n    finally:\n        os.close(fd)\n"
        if old in body:
            body = body.replace(old, new, 1)
    prov.write_text(body, encoding="utf-8")

transform = ROOT / "client/linux/apply-session-mutation.py"
if transform.exists():
    body = transform.read_text(encoding="utf-8")
    for name in ("routervpn-gtk-product.c", "routervpn-gtk-product-v3.c", "routervpn-gtk-product-v4.c", "routervpn-profile-settings-v1.inc", "routervpn-unified-shell-v8.inc"):
        source = ROOT / "client/linux" / name
        if not source.exists():
            continue
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        body, count = re.subn(rf"('{re.escape(name)}'\s*:\s*\()'[0-9a-f]{{64}}'", rf"\1'{digest}'", body, count=1)
        if count != 1:
            raise SystemExit(f"cannot update Linux transform baseline for {name}")
    transform.write_text(body, encoding="utf-8")

test_jobs = ROOT / "server/scripts/test_download_jobs.py"
if test_jobs.exists():
    body = test_jobs.read_text(encoding="utf-8")
    body = body.replace('assert not work_parent.exists(), "delivered job temp directory was not removed"', 'assert work_parent.exists(), "delivered job must remain retryable for 30 minutes"\n            delivered_public = manager.status(job_id)\n            assert delivered_public["expires_in_seconds"] > 0 and delivered_public["expires_in_seconds"] <= m.JOB_TTL_SECONDS\n            assert "download_url" in delivered_public\n            manager.reap_expired(time.time() + m.JOB_TTL_SECONDS + 2)\n            assert not work_parent.exists(), "delivered job temp directory survived its 30-minute deadline"')
    body = body.replace('assert not parent2.exists(), "interrupted delivery temp directory was not removed"', 'assert parent2.exists(), "interrupted delivery must remain retryable for 30 minutes"\n            retry_path, _ = manager.begin_delivery(second_id)\n            assert retry_path.read_bytes() == b"router-vpn-test-package"\n            manager.finish_delivery(second_id, True)\n            manager.reap_expired(time.time() + m.JOB_TTL_SECONDS + 2)\n            assert not parent2.exists(), "interrupted delivery temp directory survived its 30-minute deadline"')
    test_jobs.write_text(body, encoding="utf-8")

requirements = {
  "schema_version": 1,
  "precedence": ["verified current main source and exact-head evidence", "latest explicit user correction", "August 25 mega handoff override", "mm.md post-GitHub gates", "older uncancelled requirements"],
  "repository_policy": {"branch": "main", "branches_or_prs": False, "direct_commits": True},
  "product_split": {"setup_center": "deployment-admin-recovery", "native_app": "daily-map-first-vpn"},
  "defaults": {"surface": "map", "mode": "smart-auto", "selected_node_count": 1, "ipv6": True, "mtu_policy": "auto", "auto_require_encrypted": False, "auto_require_obfuscation": False},
  "bottom_sheet_order": ["connection", "multihop", "settings", "mode", "dns"],
  "download_delivery": {"order": ["exact-sha-release", "exact-sha-actions", "bounded-local-supported-desktop"], "mobile_local_fallback": False, "retention_seconds_from_ready": 1800, "delivery_does_not_extend_deadline": True, "cancel_or_shutdown_deletes_immediately": True},
  "truth": {"connected_requires_path_proof": True, "no_fake_coordinates_location_rtt_mbps_forwarding_or_capabilities": True, "unsupported_controls_disabled_with_reason": True, "custom_xor_cipher": False, "authenticated_standard_cryptography_only": True},
  "cancelled": ["feature branches and pull-request workflow", "browser/PWA daily app", "WSL counted as native Windows VPN", "PortableApps/PAF", "moving latest release/artifact fallback", "custom XOR or homemade packet cipher", "broad ASUS traffic ownership"]
}
write("configs/current-requirements.json", json.dumps(requirements, indent=2) + "\n")
write("docs/CURRENT-REQUIREMENTS.md", """# Router VPN Current Requirements

This file resolves conflicting historical notes. Verified current source and the latest explicit user correction win. Historical handoffs remain evidence only where not superseded.

## Binding product

- Native map-first daily app on Windows, macOS, Linux, Android, iPhone and iPad.
- Separate private Setup Center for deployment, downloads, administration, update and recovery.
- One selected node by default; SMART AUTO default; Connect/Disconnect, Multihop, Settings, Mode and DNS in the expandable control surface.
- Real-coordinate VPN map/globe, truthful role colors, route lines, packet animation, node/path RTT and real speed tests.
- Whole-connection profile Add/Load/Update/Delete without duplicating secrets.
- Auto/Fixed/Retest MTU; IPv6 On; AUTO encryption/obfuscation requirements Off by default; capability-gated kill switch, forwarding, Jumbo and DAITA-like padding.
- External nodes and bridges only where a real native dataplane exists. No invented XOR/custom cipher.

## Package delivery

Exact-SHA GitHub Release first, then exact-SHA Actions artifact, then one bounded locally supported desktop/Portable build. Mobile is artifact-only. The completed package and its owned build workspace are retained for exactly 30 minutes from READY for retry/re-download; delivery does not extend the deadline; cancel/delete/shutdown removes them immediately.

## Canceled/superseded

No branches/PRs for routine work, no browser/PWA daily client, no WSL-as-native, no PortableApps/PAF, no moving-latest artifact fallback, no fake readiness/proof/location/speed/forwarding, no homemade cryptography, and no broad ASUS rules that can own ordinary household traffic.
""")

write("deploy/current-requirements-audit.py", r'''#!/usr/bin/env python3
from __future__ import annotations
import json
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
errors: list[str] = []
def text(rel: str) -> str:
    p = ROOT / rel
    if not p.is_file(): errors.append(f"missing {rel}"); return ""
    return p.read_text(encoding="utf-8", errors="replace")
def need(rel: str, *values: str) -> None:
    body=text(rel)
    for value in values:
        if value not in body: errors.append(f"{rel}: missing {value!r}")
def forbid(rel: str, *values: str) -> None:
    body=text(rel)
    for value in values:
        if value in body: errors.append(f"{rel}: forbidden {value!r}")
cfg=json.loads(text("configs/current-requirements.json") or "{}")
assert cfg.get("repository_policy") == {"branch":"main","branches_or_prs":False,"direct_commits":True}
assert cfg.get("defaults",{}).get("mode") == "smart-auto"
assert cfg.get("defaults",{}).get("selected_node_count") == 1
assert cfg.get("defaults",{}).get("ipv6") is True
assert cfg.get("download_delivery",{}).get("retention_seconds_from_ready") == 1800
assert cfg.get("truth",{}).get("custom_xor_cipher") is False
need("deploy/materialize-production-compose.py","--sha","server/portainer-current.yaml","GENERATED exact-SHA Router VPN production compose","atomic_write")
need(".github/workflows/production-release-compose.yml","materialize-production-compose.py --sha","verify-production-compose.py")
need("deploy/package-macos-native.sh","server/scripts/source_provenance.py")
need("deploy/package-linux-native.sh","server/scripts/source_provenance.py")
need("server/scripts/build-download-on-demand.py",'Path(__file__).with_name("source_provenance.py")')
need("server/scripts/download_jobs.py","JOB_TTL_SECONDS = 30 * 60","retention_deadline_epoch=time.time() + PACKAGE_RETENTION_SECONDS")
need("deploy/setup-center-download-retention-audit.py","30-minute Setup Center download contract")
need("deploy/unified-map-shipping-audit.py","Prove the unified map control center is in each real shipping entrypoint")
for rel in ("deploy/package-macos-native.sh","deploy/package-linux-native.sh"): forbid(rel,"$ROOT/deploy/source_provenance.py")
if errors:
    print("CURRENT REQUIREMENTS RECONCILIATION: FAIL")
    for error in errors: print(" - "+error)
    raise SystemExit(1)
print("CURRENT REQUIREMENTS RECONCILIATION: PASS")
''')

# Retire temporary automation only; shipping transforms are intentionally outside .github.
for folder in (ROOT / ".github/workflows", ROOT / ".github/scripts"):
    if folder.exists():
        for p in list(folder.iterdir()):
            n=p.name.lower()
            if p.name == Path(__file__).name:
                continue
            if n.startswith("one-shot-") or n.startswith("direct-main-") or n.endswith(".trigger"):
                p.unlink()
for p in ROOT.rglob(".one-shot-*"):
    if p.is_file(): p.unlink()
print("final current-requirements reconciliation applied")
