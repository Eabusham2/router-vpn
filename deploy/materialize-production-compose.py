#!/usr/bin/env python3
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
