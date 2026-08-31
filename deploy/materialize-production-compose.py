#!/usr/bin/env python3
"""Materialize the production Portainer compose from a strict private env file."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import stat
import tempfile

REQUIRED = (
    "TZ",
    "WG_PORT",
    "AWG2_PORT",
    "XRAY_PQ_PORT",
    "XRAY_XHTTP_PORT",
    "OPENVPN_PORT",
    "SERVER_INTERNAL_CIDR",
    "SERVER_INTERNAL_GATEWAY",
    "ROUTER_LAN_CIDR",
    "CLIENT_EXTERNAL_PORT",
    "CLIENT_LISTEN",
    "SETUP_CENTER_EXTERNAL_PORT",
    "SETUP_CENTER_LISTEN",
    "ROUTER_AGENT_EXTERNAL_PORT",
    "ROUTER_AGENT_LISTEN",
    "SETUP_BASE_URL",
    "PUBLIC_ENDPOINT",
)

PORT_KEYS = {
    "WG_PORT",
    "AWG2_PORT",
    "XRAY_PQ_PORT",
    "XRAY_XHTTP_PORT",
    "OPENVPN_PORT",
    "CLIENT_EXTERNAL_PORT",
    "SETUP_CENTER_EXTERNAL_PORT",
    "ROUTER_AGENT_EXTERNAL_PORT",
}

MAX_SOURCE_BYTES = 4 << 20
MAX_OUTPUT_BYTES = 8 << 20
PUBLIC_MODE = 0o644


def load_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for lineno, raw in enumerate(path.read_text().splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise SystemExit(f"{path}:{lineno}: expected KEY=VALUE")
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
            raise SystemExit(f"{path}:{lineno}: invalid key {key!r}")
        if key in values:
            raise SystemExit(f"{path}:{lineno}: duplicate key {key}")
        if any(ch in value for ch in "\r\n\x00"):
            raise SystemExit(f"{path}:{lineno}: unsafe control character")
        values[key] = value
    missing = [key for key in REQUIRED if not values.get(key)]
    if missing:
        raise SystemExit("missing required production values: " + ", ".join(missing))
    unknown = sorted(set(values) - set(REQUIRED))
    if unknown:
        raise SystemExit("unknown production values: " + ", ".join(unknown))
    for key in PORT_KEYS:
        try:
            port = int(values[key])
        except ValueError as exc:
            raise SystemExit(f"{key} must be an integer") from exc
        if not 1 <= port <= 65535:
            raise SystemExit(f"{key} must be between 1 and 65535")
    for key in ("CLIENT_LISTEN", "SETUP_CENTER_LISTEN", "ROUTER_AGENT_LISTEN"):
        if not re.fullmatch(r"[^\s:]+:\d+", values[key]):
            raise SystemExit(f"{key} must be host:port")
    if not values["SETUP_BASE_URL"].startswith(("http://", "https://")):
        raise SystemExit("SETUP_BASE_URL must be an http(s) URL")
    if values["PUBLIC_ENDPOINT"] in {"router.invalid", "replace-me"}:
        raise SystemExit("PUBLIC_ENDPOINT is still a placeholder")
    return values


def materialize(template: str, values: dict[str, str]) -> str:
    output = template
    for key in REQUIRED:
        token = "${" + key + "}"
        output = output.replace(token, values[key])
    leftovers = sorted(set(re.findall(r"\$\{([A-Z][A-Z0-9_]*)\}", output)))
    if leftovers:
        raise SystemExit("unresolved compose variables: " + ", ".join(leftovers))
    for placeholder in (
        "router.invalid",
        "REPLACE_ME",
        "SET_ME",
        "TODO",
        "CHANGEME",
        "example.invalid",
    ):
        if placeholder in output:
            raise SystemExit(f"materialized compose still contains placeholder {placeholder!r}")
    return output


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
    if (
        stat.S_ISLNK(current.st_mode)
        or not stat.S_ISREG(current.st_mode)
        or not os.path.samestat(expected, current)
    ):
        raise RuntimeError(f"compose target identity changed before adoption: {path}")


def read_regular_text(path: Path) -> str:
    path = Path(path)
    parent_before = _parent_snapshot(path)
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise RuntimeError(f"refusing non-regular/symlink compose source: {path}")
    if info.st_size <= 0 or info.st_size > MAX_SOURCE_BYTES:
        raise RuntimeError(f"compose source is empty or oversized: {path}")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(fd)
        current = path.lstat()
        if stat.S_ISLNK(current.st_mode) or not stat.S_ISREG(current.st_mode) or not os.path.samestat(opened, current):
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
        if (
            not os.path.samestat(parent_before, parent_after)
            or stat.S_ISLNK(current.st_mode)
            or not stat.S_ISREG(current.st_mode)
            or not os.path.samestat(opened, current)
        ):
            raise RuntimeError(f"compose source changed during read: {path}")
        body = b"".join(chunks)
    finally:
        os.close(fd)
    try:
        return body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RuntimeError(f"compose source is not UTF-8: {path}") from exc


def atomic_write(path: Path, body: str) -> None:
    path = Path(path)
    encoded = body.encode("utf-8")
    if not encoded or len(encoded) > MAX_OUTPUT_BYTES:
        raise RuntimeError(f"materialized compose is empty or oversized: {path}")
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
        if (
            stat.S_ISLNK(staged.st_mode)
            or not stat.S_ISREG(staged.st_mode)
            or (os.name != "nt" and stat.S_IMODE(staged.st_mode) != PUBLIC_MODE)
        ):
            raise RuntimeError(f"staged compose target is unsafe: {tmp}")

        parent_current = _parent_snapshot(path)
        if not os.path.samestat(parent_before, parent_current):
            raise RuntimeError(f"compose parent changed before adoption: {path.parent}")
        _require_target_state(path, target_before)
        os.replace(tmp, path)
        committed = True

        parent_after = _parent_snapshot(path)
        current = path.lstat()
        if (
            not os.path.samestat(parent_before, parent_after)
            or stat.S_ISLNK(current.st_mode)
            or not stat.S_ISREG(current.st_mode)
            or (os.name != "nt" and stat.S_IMODE(current.st_mode) != PUBLIC_MODE)
            or not os.path.samestat(staged, current)
        ):
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
    parser = argparse.ArgumentParser()
    parser.add_argument("--template", type=Path, required=True)
    parser.add_argument("--env", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    values = load_env_from_text(args.env, read_regular_text(args.env))
    rendered = materialize(read_regular_text(args.template), values)
    atomic_write(args.output, rendered)
    return 0


def load_env_from_text(path: Path, text: str) -> dict[str, str]:
    # Preserve load_env's public contract while allowing main() to consume a
    # single verified source snapshot instead of reopening the path.
    values: dict[str, str] = {}
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise SystemExit(f"{path}:{lineno}: expected KEY=VALUE")
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
            raise SystemExit(f"{path}:{lineno}: invalid key {key!r}")
        if key in values:
            raise SystemExit(f"{path}:{lineno}: duplicate key {key}")
        if any(ch in value for ch in "\r\n\x00"):
            raise SystemExit(f"{path}:{lineno}: unsafe control character")
        values[key] = value
    missing = [key for key in REQUIRED if not values.get(key)]
    if missing:
        raise SystemExit("missing required production values: " + ", ".join(missing))
    unknown = sorted(set(values) - set(REQUIRED))
    if unknown:
        raise SystemExit("unknown production values: " + ", ".join(unknown))
    for key in PORT_KEYS:
        try:
            port = int(values[key])
        except ValueError as exc:
            raise SystemExit(f"{key} must be an integer") from exc
        if not 1 <= port <= 65535:
            raise SystemExit(f"{key} must be between 1 and 65535")
    for key in ("CLIENT_LISTEN", "SETUP_CENTER_LISTEN", "ROUTER_AGENT_LISTEN"):
        if not re.fullmatch(r"[^\s:]+:\d+", values[key]):
            raise SystemExit(f"{key} must be host:port")
    if not values["SETUP_BASE_URL"].startswith(("http://", "https://")):
        raise SystemExit("SETUP_BASE_URL must be an http(s) URL")
    if values["PUBLIC_ENDPOINT"] in {"router.invalid", "replace-me"}:
        raise SystemExit("PUBLIC_ENDPOINT is still a placeholder")
    return values


if __name__ == "__main__":
    raise SystemExit(main())
