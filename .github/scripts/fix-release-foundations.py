#!/usr/bin/env python3
from pathlib import Path
import hashlib
import os
import re

ROOT = Path(__file__).resolve().parents[2]

# Native package archives embed the package-family provenance manifest.  The
# release-level deploy/source_provenance.py only verifies/combines finished
# artifacts; it is not the package writer.
for rel, family_expr in (
    ("deploy/package-macos-native.sh", "macos-$arch"),
    ("deploy/package-linux-native.sh", "linux-$arch"),
):
    path = ROOT / rel
    text = path.read_text(encoding="utf-8")
    root_anchor = 'ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)\n'
    if "SOURCE_SHA=" not in text:
        if root_anchor not in text:
            raise SystemExit(f"{rel}: ROOT anchor is missing")
        text = text.replace(
            root_anchor,
            root_anchor + 'SOURCE_SHA=${ROUTER_VPN_SOURCE_SHA:-${GITHUB_SHA:-$(git -C "$ROOT" rev-parse HEAD)}}\n',
            1,
        )
    old = f'python3 "$ROOT/deploy/source_provenance.py" "$dir" --family "{family_expr}"'
    new = f'python3 "$ROOT/server/scripts/source_provenance.py" "$dir" --sha "$SOURCE_SHA" --family "{family_expr}"'
    text = text.replace(old, new)
    text = re.sub(
        rf'python3 "\$ROOT/server/scripts/source_provenance\.py" "\$dir"(?: --sha "[^"]+")? --family "{re.escape(family_expr)}"',
        new,
        text,
    )
    if new not in text:
        raise SystemExit(f"{rel}: package provenance invocation was not normalized")
    path.write_text(text, encoding="utf-8")

materializer = r'''#!/usr/bin/env python3
"""Materialize ``server/portainer-current.yaml`` for one exact release SHA.

The tracked file is a reviewed image-only baseline/template. Release workflows
produce a separate ``# GENERATED exact-SHA Router VPN production compose`` and
never overwrite the tracked template. Every Router VPN custom image and the
Setup Center broker SHA are rebound to the same requested 40-hex commit.
"""
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
    if current is None or stat.S_ISLNK(current.st_mode) or not stat.S_ISREG(current.st_mode) or not os.path.samestat(expected, current):
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
        body = b"".join(chunks)
    finally:
        os.close(fd)
    try:
        return body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RuntimeError(f"compose source is not UTF-8: {path}") from exc


def validate_template(text: str) -> str:
    if re.search(r"(?m)^\s*build:\s*$", text):
        fail("production template must stay image-only")
    if re.search(r"(?m)^\s*context:\s*https?://", text):
        fail("production template may not use a remote Git build context")
    if re.search(r"(?m)^\s*image:\s*\S+:(?:latest|main|arm64-main)\s*$", text):
        fail("production template may not use moving Router VPN images")
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
    if not broker or broker.group(2) != found[0]:
        fail("production template broker SHA must equal the custom image baseline SHA")
    return found[0]


def materialize(text: str, target_sha: str) -> str:
    target_sha = str(target_sha or "").strip().lower()
    if not SHA_RE.fullmatch(target_sha):
        fail("--sha must be one lowercase 40-character hexadecimal commit SHA")
    baseline = validate_template(text)
    rendered, image_count = IMAGE_RE.subn(lambda match: match.group(1) + target_sha, text)
    rendered, broker_count = BROKER_RE.subn(lambda match: match.group(1) + target_sha + match.group(3), rendered)
    expected_images = sum(CUSTOM_IMAGES.values())
    if image_count != expected_images or broker_count != 1:
        fail(f"exact-SHA replacement count mismatch: images={image_count}/{expected_images}, broker={broker_count}/1")
    if validate_template(rendered) != target_sha:
        fail("materialized compose did not converge on the requested exact SHA")
    header = (
        f"# GENERATED exact-SHA Router VPN production compose: {target_sha}\n"
        f"# Source template: server/portainer-current.yaml (baseline SHA {baseline})\n"
        "# Do not commit this generated release artifact over the tracked baseline/template.\n"
    )
    return header + rendered


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
    adopted = False
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
        adopted = True
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
        if not adopted:
            tmp.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Materialize one exact-SHA Router VPN Portainer compose.")
    parser.add_argument("--sha", required=True)
    parser.add_argument("--input", default="server/portainer-current.yaml", dest="input_path")
    parser.add_argument("--output", required=True, dest="output_path")
    args = parser.parse_args()
    rendered = materialize(read_regular_text(Path(args.input_path)), args.sha)
    atomic_write(Path(args.output_path), rendered)
    print(f"Materialized {args.output_path} for exact release SHA {args.sha}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''
(ROOT / "deploy/materialize-production-compose.py").write_text(materializer, encoding="utf-8")
os.chmod(ROOT / "deploy/materialize-production-compose.py", 0o755)

test = r'''#!/usr/bin/env python3
from __future__ import annotations
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "deploy/materialize-production-compose.py"
VERIFY = ROOT / "server/scripts/verify-production-compose.py"
SOURCE = ROOT / "server/portainer-current.yaml"
TARGET = "a" * 40

def load_module():
    spec = importlib.util.spec_from_file_location("routervpn_materializer", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def main() -> int:
    prod = load_module()
    original = SOURCE.read_bytes()
    with tempfile.TemporaryDirectory(prefix="router-vpn-production-compose-") as td:
        root = Path(td)
        out = root / f"RouterVPN-Portainer-{TARGET}.yaml"
        subprocess.run([sys.executable, str(SCRIPT), "--sha", TARGET, "--input", str(SOURCE), "--output", str(out)], cwd=ROOT, check=True)
        rendered = out.read_text(encoding="utf-8")
        assert rendered.startswith("# GENERATED exact-SHA Router VPN production compose: " + TARGET)
        assert "# Source template: server/portainer-current.yaml" in rendered
        assert SOURCE.read_bytes() == original
        verified = subprocess.run([sys.executable, str(VERIFY), str(out)], cwd=ROOT, text=True, stdout=subprocess.PIPE, check=True)
        assert verified.stdout.strip() == TARGET
        assert all(sha == TARGET for _, sha in prod.IMAGE_RE.findall(rendered))
        assert prod.BROKER_RE.search(rendered).group(2) == TARGET
        bad = subprocess.run([sys.executable, str(SCRIPT), "--sha", "not-a-sha", "--input", str(SOURCE), "--output", str(out)], cwd=ROOT)
        assert bad.returncode != 0
        output = root / "race.yaml"
        prod.atomic_write(output, "old\n")
        foreign = root / "foreign.yaml"
        foreign.write_text("foreign\n", encoding="utf-8")
        os.chmod(foreign, 0o644)
        real_require = prod._require_target_state
        swapped = False
        def swap_target(path, expected):
            nonlocal swapped
            if not swapped:
                swapped = True
                os.replace(foreign, path)
            return real_require(path, expected)
        with mock.patch.object(prod, "_require_target_state", side_effect=swap_target):
            try:
                prod.atomic_write(output, "new\n")
            except RuntimeError as exc:
                assert "identity changed" in str(exc)
            else:
                raise AssertionError("compose writer overwrote a foreign target")
        assert output.read_text() == "foreign\n"
        assert not list(root.glob(".race.yaml.compose-*"))
    workflow = (ROOT / ".github/workflows/production-release-compose.yml").read_text()
    for marker in ("materialize-production-compose.py --sha \"$GITHUB_SHA\"", "verify-production-compose.py", "RouterVPN-production-compose-${{ github.sha }}"):
        assert marker in workflow, marker
    print("production release compose materializer tests passed")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
'''
(ROOT / "deploy/test-production-release-compose.py").write_text(test, encoding="utf-8")
os.chmod(ROOT / "deploy/test-production-release-compose.py", 0o755)

# The session transformer deliberately refuses source drift. Refresh only the
# canonical unified-shell baseline after the map-first source was reviewed.
transform = ROOT / "client/linux/apply-session-mutation.py"
source = ROOT / "client/linux/routervpn-unified-shell-v8.inc"
text = transform.read_text(encoding="utf-8")
digest = hashlib.sha256(source.read_bytes()).hexdigest()
matches = re.findall(r"'routervpn-unified-shell-v8\.inc'\s*:\s*\('([0-9a-f]{64})'", text)
if len(matches) != 1:
    raise SystemExit("cannot locate one Linux unified-shell baseline hash")
transform.write_text(text.replace(matches[0], digest, 1), encoding="utf-8")
print("release foundations reconciled")
