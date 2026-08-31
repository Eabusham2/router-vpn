#!/usr/bin/env python3
"""One-shot main-only reconciliation of current shipping/release contracts."""
from __future__ import annotations

import hashlib
from pathlib import Path
import re

ROOT = Path.cwd()
changed: list[str] = []


def write(path: str, content: str) -> None:
    target = ROOT / path
    previous = target.read_text(encoding="utf-8") if target.exists() else None
    if previous != content:
        target.write_text(content, encoding="utf-8")
        changed.append(path)


# Native package provenance and release-manifest provenance are separate APIs.
# Packages must embed ROUTER-VPN-SOURCE.json with the package writer.
for rel in ("deploy/package-macos-native.sh", "deploy/package-linux-native.sh"):
    target = ROOT / rel
    body = target.read_text(encoding="utf-8")
    body = body.replace(
        '"$ROOT/deploy/source_provenance.py"',
        '"$ROOT/server/scripts/source_provenance.py"',
    )
    write(rel, body)


# Deterministic Linux transforms intentionally pin each canonical shipping
# input. Refresh only the recorded hashes; the transformer continues to fail
# closed on any unreviewed future source drift.
transform_path = ROOT / "client/linux/apply-session-mutation.py"
transform = transform_path.read_text(encoding="utf-8")
for name in (
    "routervpn-gtk-product.c",
    "routervpn-gtk-product-v3.c",
    "routervpn-gtk-product-v4.c",
    "routervpn-profile-settings-v1.inc",
    "routervpn-unified-shell-v8.inc",
):
    source = ROOT / "client/linux" / name
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    pattern = re.compile(r"('" + re.escape(name) + r"'\s*:\s*\(')([0-9a-f]{64})(')")
    transform, count = pattern.subn(lambda m: m.group(1) + digest + m.group(3), transform, count=1)
    if count != 1:
        raise RuntimeError(f"could not refresh Linux transform baseline for {name}")
write("client/linux/apply-session-mutation.py", transform)


materializer = r'''#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from typing import NoReturn

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
HEADER_PREFIX = "# GENERATED exact-SHA Router VPN production compose: "
DEFAULT_TEMPLATE = "server/portainer-current.yaml"
MAX_SOURCE_BYTES = 8 << 20
PUBLIC_MODE = 0o644


def fail(message: str) -> NoReturn:
    raise SystemExit(message)


def _parent_snapshot(path: Path) -> os.stat_result:
    info = path.parent.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise RuntimeError(f"refusing unsafe production-compose parent: {path.parent}")
    return info


def _target_snapshot(path: Path) -> os.stat_result | None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise RuntimeError(f"refusing non-regular/symlink production-compose target: {path}")
    return info


def _require_target_state(path: Path, expected: os.stat_result | None) -> None:
    try:
        current = path.lstat()
    except FileNotFoundError:
        current = None
    if expected is None:
        if current is not None:
            raise RuntimeError(f"production-compose target appeared before adoption: {path}")
        return
    if (
        current is None
        or stat.S_ISLNK(current.st_mode)
        or not stat.S_ISREG(current.st_mode)
        or not os.path.samestat(expected, current)
    ):
        raise RuntimeError(f"production-compose target identity changed before adoption: {path}")


def read_regular_text(path: Path) -> str:
    path = Path(path)
    parent_before = _parent_snapshot(path)
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise RuntimeError(f"refusing non-regular/symlink production template: {path}")
    if before.st_size <= 0 or before.st_size > MAX_SOURCE_BYTES:
        raise RuntimeError(f"production template is empty or oversized: {path}")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(fd)
        current = path.lstat()
        if (
            stat.S_ISLNK(current.st_mode)
            or not stat.S_ISREG(current.st_mode)
            or not os.path.samestat(before, opened)
            or not os.path.samestat(opened, current)
        ):
            raise RuntimeError(f"production template changed during open: {path}")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(1 << 20, MAX_SOURCE_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_SOURCE_BYTES:
                raise RuntimeError(f"production template exceeds safety limit: {path}")
        parent_after = _parent_snapshot(path)
        current = path.lstat()
        if (
            not os.path.samestat(parent_before, parent_after)
            or stat.S_ISLNK(current.st_mode)
            or not stat.S_ISREG(current.st_mode)
            or not os.path.samestat(opened, current)
        ):
            raise RuntimeError(f"production template changed during read: {path}")
        raw = b"".join(chunks)
    finally:
        os.close(fd)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RuntimeError(f"production template is not UTF-8: {path}") from exc


def validate_template(text: str) -> str:
    if HEADER_PREFIX in text:
        fail("tracked production template must not already be generated")
    if re.search(r"(?m)^\s*build:\s*$", text):
        fail("production template must stay image-only")
    if re.search(r"(?m)^\s*context:\s*https?://", text):
        fail("production template may not use a remote Git build context")
    if re.search(r"ghcr\.io/eabusham2/router-vpn-[^\s:]+:(?:latest|main|arm64-main)\b", text):
        fail("production template may not use moving Router VPN image tags")
    if "/var/run/docker.sock" in text:
        fail("production template may not grant Docker socket access")

    found: list[str] = []
    for image, expected in CUSTOM_IMAGES.items():
        matches = re.findall(
            rf"ghcr\.io/eabusham2/router-vpn-{re.escape(image)}:([0-9a-f]{{40}})",
            text,
        )
        if len(matches) != expected:
            fail(
                f"expected {expected} exact-SHA template references for "
                f"router-vpn-{image}, found {len(matches)}"
            )
        found.extend(matches)
    if not found or len(set(found)) != 1:
        fail("production template custom images must share one exact baseline SHA")
    broker = BROKER_RE.search(text)
    if not broker:
        fail("production template broker provenance is not a full SHA")
    if broker.group(2) != found[0]:
        fail("production template broker SHA does not match custom image SHA")
    if "ROUTER_VPN_UPDATE_LISTEN: 127.0.0.1:8793" not in text:
        fail("production updater must remain loopback-only")
    return found[0]


def materialize(text: str, target_sha: str) -> str:
    target_sha = str(target_sha or "").strip().lower()
    if not SHA_RE.fullmatch(target_sha):
        fail("--sha must be one lowercase 40-character hexadecimal commit SHA")
    baseline = validate_template(text)
    out, image_replacements = IMAGE_RE.subn(lambda match: match.group(1) + target_sha, text)
    out, broker_replacements = BROKER_RE.subn(
        lambda match: match.group(1) + target_sha + match.group(3),
        out,
    )
    expected_images = sum(CUSTOM_IMAGES.values())
    if image_replacements != expected_images:
        fail(f"expected {expected_images} custom image replacements, made {image_replacements}")
    if broker_replacements != 1:
        fail(f"expected one broker SHA replacement, made {broker_replacements}")
    if any(sha != target_sha for _, sha in IMAGE_RE.findall(out)):
        fail("materialized compose contains a non-target custom image SHA")
    broker = BROKER_RE.search(out)
    if not broker or broker.group(2) != target_sha:
        fail("materialized compose broker provenance does not equal target SHA")
    return (
        f"{HEADER_PREFIX}{target_sha}\n"
        f"# Source template baseline SHA: {baseline}\n"
        f"# Source template: {DEFAULT_TEMPLATE}\n"
        "# Do not commit this generated file over server/portainer-current.yaml.\n"
        + out
    )


def atomic_write(path: Path, body: str) -> None:
    path = Path(path)
    encoded = body.encode("utf-8")
    if not encoded or len(encoded) > MAX_SOURCE_BYTES:
        raise RuntimeError(f"generated production compose is empty or oversized: {path}")
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
        if (
            stat.S_ISLNK(staged.st_mode)
            or not stat.S_ISREG(staged.st_mode)
            or (os.name != "nt" and stat.S_IMODE(staged.st_mode) != PUBLIC_MODE)
        ):
            raise RuntimeError("staged production compose is unsafe")
        if not os.path.samestat(parent_before, _parent_snapshot(path)):
            raise RuntimeError("production-compose parent changed before adoption")
        _require_target_state(path, target_before)
        os.replace(tmp, path)
        adopted = True
        current = path.lstat()
        parent_after = _parent_snapshot(path)
        if (
            not os.path.samestat(parent_before, parent_after)
            or stat.S_ISLNK(current.st_mode)
            or not stat.S_ISREG(current.st_mode)
            or not os.path.samestat(staged, current)
        ):
            raise RuntimeError("adopted production-compose identity changed before verification")
        try:
            directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError:
            pass
    finally:
        if not adopted:
            tmp.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Materialize server/portainer-current.yaml for one exact release commit."
    )
    parser.add_argument("--sha", required=True)
    parser.add_argument("--input", default=DEFAULT_TEMPLATE, dest="input_path")
    parser.add_argument("--output", required=True, dest="output_path")
    args = parser.parse_args()
    source = Path(args.input_path)
    output = Path(args.output_path)
    rendered = materialize(read_regular_text(source), args.sha)
    atomic_write(output, rendered)
    print(f"Materialized {output} for exact release SHA {args.sha}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''
write("deploy/materialize-production-compose.py", materializer)


test_source = r'''#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "deploy/materialize-production-compose.py"
VERIFY = ROOT / "server/scripts/verify-production-compose.py"
SOURCE = ROOT / "server/portainer-current.yaml"
TARGET = "a" * 40


def load_module():
    spec = importlib.util.spec_from_file_location("routervpn_production", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    module = load_module()
    original = SOURCE.read_bytes()
    with tempfile.TemporaryDirectory(prefix="router-vpn-production-compose-") as td:
        root = Path(td)
        output = root / f"RouterVPN-Portainer-{TARGET}.yaml"
        subprocess.run(
            [
                os.sys.executable,
                str(SCRIPT),
                "--sha",
                TARGET,
                "--input",
                str(SOURCE),
                "--output",
                str(output),
            ],
            cwd=ROOT,
            check=True,
        )
        rendered = output.read_text(encoding="utf-8")
        assert rendered.startswith(
            "# GENERATED exact-SHA Router VPN production compose: " + TARGET + "\n"
        )
        assert "# Source template: server/portainer-current.yaml" in rendered
        assert "ROUTER_VPN_GITHUB_SHA: " + TARGET in rendered
        assert SOURCE.read_bytes() == original, "materializer mutated tracked baseline"
        verified = subprocess.run(
            [os.sys.executable, str(VERIFY), str(output)],
            cwd=ROOT,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        )
        assert verified.stdout.strip() == TARGET
        baseline = subprocess.run(
            [os.sys.executable, str(VERIFY), str(SOURCE)],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        assert baseline.returncode != 0, "tracked template was accepted as generated compose"
        invalid = subprocess.run(
            [os.sys.executable, str(SCRIPT), "--sha", "not-a-sha", "--output", str(output)],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        assert invalid.returncode != 0

        previous = b"previous-valid-compose\n"
        output.write_bytes(previous)
        os.chmod(output, 0o644)
        with mock.patch.object(module.os, "replace", side_effect=RuntimeError("injected adoption failure")):
            try:
                module.atomic_write(output, "new compose\n")
            except RuntimeError as exc:
                assert "injected" in str(exc)
            else:
                raise AssertionError("injected adoption failure was ignored")
        assert output.read_bytes() == previous
        assert not list(root.glob(".*.compose-*"))

        if os.name != "nt":
            outside = root / "outside"
            outside.write_text("keep\n", encoding="utf-8")
            linked = root / "linked.yaml"
            linked.symlink_to(outside)
            try:
                module.atomic_write(linked, "replace\n")
            except RuntimeError as exc:
                assert "symlink" in str(exc)
            else:
                raise AssertionError("symlink output was accepted")
            assert outside.read_text(encoding="utf-8") == "keep\n"

    workflow = (ROOT / ".github/workflows/production-release-compose.yml").read_text(
        encoding="utf-8"
    )
    for marker in (
        '--sha "$GITHUB_SHA"',
        '--output "$out"',
        "GENERATED exact-SHA Router VPN production compose",
        "verify-production-compose.py",
    ):
        assert marker in workflow, marker
    assert "--template" not in workflow and "--env" not in workflow
    print("production release compose materializer tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''
write("deploy/test-production-release-compose.py", test_source)


workflow_path = ROOT / ".github/workflows/production-release-compose.yml"
workflow = workflow_path.read_text(encoding="utf-8")
workflow = workflow.replace(
    'python3 deploy/materialize-production-compose.py --template server/portainer-current.yaml --env "$ENV_FILE" --output "$out"',
    'python3 deploy/materialize-production-compose.py --sha "$GITHUB_SHA" --input server/portainer-current.yaml --output "$out"',
)
write(".github/workflows/production-release-compose.yml", workflow)

print("Reconciled files:")
for path in changed:
    print(" -", path)
