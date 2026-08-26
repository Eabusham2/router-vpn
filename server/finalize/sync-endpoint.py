#!/usr/bin/env python3
from __future__ import annotations

import ipaddress
import json
import os
import pathlib
import re
import stat
import sys
import tempfile
from dataclasses import dataclass
from typing import Iterable

MAX_OWNED_FILE = 4 << 20
PRIVATE_MODE = 0o600

RAW_PROFILES = {
    "wg": ("wg.conf", "wg-socks.conf"),
    "wg-pq": ("wg.conf", "wg-socks.conf"),
    "awg2-fast": ("awg.conf", "awg-socks.conf"),
    "awg2-strong": ("awg.conf", "awg-socks.conf"),
    "awg2-pq": ("awg.conf", "awg-socks.conf"),
}
ENDPOINT_LINE = re.compile(
    r"(?m)^(\s*Endpoint\s*=\s*)(?:\[[^\]]+\]|[^:\s]+):(\d+)\s*$"
)


@dataclass(frozen=True)
class Change:
    path: pathlib.Path
    before: bytes
    after: bytes


def parse_endpoint(value: str) -> tuple[str, str]:
    endpoint = value.strip().strip("[]")
    if not endpoint or endpoint == "router.invalid":
        raise ValueError("refusing to sync an empty/placeholder endpoint")
    try:
        parsed = ipaddress.ip_address(endpoint)
        rendered = f"[{parsed}]" if parsed.version == 6 else str(parsed)
        return str(parsed), rendered
    except ValueError:
        if not re.fullmatch(r"(?i)[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", endpoint):
            raise ValueError("invalid endpoint")
        endpoint = endpoint.lower()
        return endpoint, endpoint


def ensure_owned_parent(path: pathlib.Path) -> None:
    parent = path.parent
    info = parent.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise RuntimeError(f"refusing non-directory/symlink owned parent: {parent}")


def read_owned_file(path: pathlib.Path) -> bytes:
    ensure_owned_parent(path)
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise RuntimeError(f"refusing non-regular/symlink owned file: {path}")
    if info.st_size > MAX_OWNED_FILE:
        raise RuntimeError(f"owned file exceeds safety limit: {path}")

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        current = path.lstat()
        if stat.S_ISLNK(current.st_mode) or not stat.S_ISREG(current.st_mode) or not os.path.samestat(opened, current):
            raise RuntimeError(f"owned file changed during open: {path}")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(64 * 1024, MAX_OWNED_FILE + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_OWNED_FILE:
                raise RuntimeError(f"owned file exceeds safety limit: {path}")
        return b"".join(chunks)
    finally:
        os.close(fd)


def build_changes(base: pathlib.Path, endpoint: str, rendered: str) -> list[Change]:
    changes: list[Change] = []
    raw_patched = 0

    # Endpoint sync owns only direct Router VPN WireGuard-family endpoint fields.
    # It must never scan/replace arbitrary JSON server/address fields or rewrite a
    # linked external node simply because it also has an `endpoint` property.
    for mode, names in RAW_PROFILES.items():
        for name in names:
            path = base / "client-bundle" / "generated" / mode / name
            if not path.exists():
                continue
            before = read_owned_file(path)
            try:
                text = before.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise RuntimeError(f"owned tunnel profile is not UTF-8: {path}") from exc
            updated, count = ENDPOINT_LINE.subn(
                lambda match: f"{match.group(1)}{rendered}:{match.group(2)}", text
            )
            if count:
                after = updated.encode("utf-8")
                if after != before:
                    changes.append(Change(path, before, after))
                raw_patched += 1

    if raw_patched == 0:
        raise RuntimeError("no raw WireGuard/AmneziaWG Endpoint lines were found")

    routers_path = base / "client-bundle" / "routers.json"
    if routers_path.exists():
        before = read_owned_file(routers_path)
        try:
            routers = json.loads(before.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError("routers.json is invalid") from exc
        profiles = routers.get("profiles", []) if isinstance(routers, dict) else []
        owned: list[dict] = []
        if isinstance(profiles, list):
            for profile in profiles:
                if not isinstance(profile, dict):
                    continue
                # create-bundle-json.py owns exactly the local home Router VPN
                # profile. Other linked Router VPN nodes and all external nodes
                # are user/import data and are outside this server's authority.
                if str(profile.get("id") or "").strip() != "home":
                    continue
                kind = str(profile.get("node_kind") or "router-vpn").strip().lower()
                if kind == "router-vpn":
                    owned.append(profile)
        if len(owned) > 1:
            raise RuntimeError("routers.json contains multiple owned home Router VPN profiles")
        if owned:
            owned[0]["endpoint"] = endpoint
            after = (json.dumps(routers, indent=2) + "\n").encode("utf-8")
            if after != before:
                changes.append(Change(routers_path, before, after))

    return changes


def stage_private(path: pathlib.Path, data: bytes) -> pathlib.Path:
    ensure_owned_parent(path)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.endpoint-", dir=path.parent)
    tmp = pathlib.Path(name)
    try:
        os.fchmod(fd, PRIVATE_MODE)
        with os.fdopen(fd, "wb", closefd=True) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        return tmp
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        tmp.unlink(missing_ok=True)
        raise


def fsync_directory(path: pathlib.Path) -> None:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise RuntimeError(f"refusing non-directory/symlink owned parent: {path}")
    flags = getattr(os, "O_DIRECTORY", 0) | os.O_RDONLY
    fd = os.open(path, flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def restore_changes(changes: Iterable[Change]) -> list[str]:
    errors: list[str] = []
    for change in changes:
        tmp: pathlib.Path | None = None
        try:
            tmp = stage_private(change.path, change.before)
            ensure_owned_parent(change.path)
            os.replace(tmp, change.path)
            tmp = None
            fsync_directory(change.path.parent)
        except Exception as exc:
            # Rollback must attempt every already-adopted file and report every
            # recovery failure instead of pretending the transaction completed.
            errors.append(f"{change.path}: {exc}")
        finally:
            if tmp is not None:
                tmp.unlink(missing_ok=True)
    return errors


def apply_transaction(changes: list[Change]) -> None:
    staged: dict[pathlib.Path, pathlib.Path] = {}
    adopted: list[Change] = []
    try:
        # Validate/compute happened in build_changes(). Stage every private
        # replacement before changing any authoritative path.
        for change in changes:
            staged[change.path] = stage_private(change.path, change.after)

        for change in changes:
            ensure_owned_parent(change.path)
            tmp = staged.pop(change.path)
            os.replace(tmp, change.path)
            adopted.append(change)
            fsync_directory(change.path.parent)
    except Exception as exc:
        rollback_errors = restore_changes(reversed(adopted))
        detail = f"endpoint synchronization failed and prior files were restored: {exc}"
        if rollback_errors:
            detail = (
                f"endpoint synchronization failed and rollback was incomplete: {exc}; "
                + "; ".join(rollback_errors)
            )
        raise RuntimeError(detail) from exc
    finally:
        for tmp in staged.values():
            tmp.unlink(missing_ok=True)


def sync(base: pathlib.Path, value: str) -> int:
    endpoint, rendered = parse_endpoint(value)
    changes = build_changes(base, endpoint, rendered)
    apply_transaction(changes)
    return sum(1 for change in changes if change.path.name != "routers.json")


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        raise SystemExit("usage: sync-endpoint.py BASE ENDPOINT")
    try:
        patched = sync(pathlib.Path(argv[1]), argv[2])
    except (ValueError, RuntimeError, OSError) as exc:
        raise SystemExit(str(exc)) from exc
    endpoint, _ = parse_endpoint(argv[2])
    print(
        f"Synced endpoint {endpoint} into {patched} raw tunnel profile files "
        "and the owned home Router VPN profile only."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
