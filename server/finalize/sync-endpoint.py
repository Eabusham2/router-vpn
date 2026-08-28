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
    before_stat: os.stat_result
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


def _validate_owned_ancestors(parent: pathlib.Path) -> None:
    for current in (parent, *parent.parents):
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise RuntimeError(f"refusing non-directory/symlink owned path component: {current}")


def ensure_owned_parent(path: pathlib.Path) -> None:
    parent = path.parent
    _validate_owned_ancestors(parent)
    info = parent.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise RuntimeError(f"refusing non-directory/symlink owned parent: {parent}")
    _validate_owned_ancestors(parent)


def read_owned_file_snapshot(path: pathlib.Path) -> tuple[bytes, os.stat_result]:
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
        # Older generated files may predate the strict private-mode contract.
        # Harden the already-open verified inode before reading instead of
        # following/chmodding the pathname after validation.
        if opened.st_mode & 0o077:
            os.fchmod(fd, PRIVATE_MODE)
            opened = os.fstat(fd)
        if opened.st_mode & 0o777 != PRIVATE_MODE:
            raise RuntimeError(f"owned file could not be hardened to mode 0600: {path}")
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
        ensure_owned_parent(path)
        current = path.lstat()
        if stat.S_ISLNK(current.st_mode) or not stat.S_ISREG(current.st_mode) or not os.path.samestat(opened, current):
            raise RuntimeError(f"owned file changed during read: {path}")
        return b"".join(chunks), current
    finally:
        os.close(fd)


def read_owned_file(path: pathlib.Path) -> bytes:
    body, _ = read_owned_file_snapshot(path)
    return body


def require_owned_state(path: pathlib.Path, expected: os.stat_result, label: str) -> None:
    ensure_owned_parent(path)
    try:
        current = path.lstat()
    except FileNotFoundError as exc:
        raise RuntimeError(f"{label} disappeared before adoption: {path}") from exc
    if (
        stat.S_ISLNK(current.st_mode)
        or not stat.S_ISREG(current.st_mode)
        or not os.path.samestat(expected, current)
    ):
        raise RuntimeError(f"{label} identity changed before adoption: {path}")


def build_changes(base: pathlib.Path, endpoint: str, rendered: str) -> list[Change]:
    changes: list[Change] = []
    raw_patched = 0

    # Endpoint sync owns only direct Router VPN WireGuard-family endpoint fields.
    # It must never scan/replace arbitrary JSON server/address fields or rewrite a
    # linked external node simply because it also has an `endpoint` property.
    for mode, names in RAW_PROFILES.items():
        for name in names:
            path = base / "client-bundle" / "generated" / mode / name
            try:
                path.lstat()
            except FileNotFoundError:
                continue
            before, before_stat = read_owned_file_snapshot(path)
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
                    changes.append(Change(path, before, before_stat, after))
                raw_patched += 1

    if raw_patched == 0:
        raise RuntimeError("no raw WireGuard/AmneziaWG Endpoint lines were found")

    routers_path = base / "client-bundle" / "routers.json"
    try:
        routers_path.lstat()
        routers_present = True
    except FileNotFoundError:
        routers_present = False
    if routers_present:
        before, before_stat = read_owned_file_snapshot(routers_path)
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
                changes.append(Change(routers_path, before, before_stat, after))

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
    _validate_owned_ancestors(path)
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise RuntimeError(f"refusing non-directory/symlink owned parent: {path}")
    flags = getattr(os, "O_DIRECTORY", 0) | os.O_RDONLY
    fd = os.open(path, flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def restore_changes(changes: Iterable[tuple[Change, os.stat_result]]) -> list[str]:
    errors: list[str] = []
    for change, adopted_stat in changes:
        tmp: pathlib.Path | None = None
        try:
            # Rollback owns only the exact inode this transaction adopted. If
            # another actor replaced it after adoption, preserve that foreign
            # state and report incomplete recovery instead of clobbering it.
            require_owned_state(change.path, adopted_stat, "adopted endpoint file")
            tmp = stage_private(change.path, change.before)
            require_owned_state(change.path, adopted_stat, "adopted endpoint file")
            os.replace(tmp, change.path)
            tmp = None
            fsync_directory(change.path.parent)
        except Exception as exc:
            errors.append(f"{change.path}: {exc}")
        finally:
            if tmp is not None:
                tmp.unlink(missing_ok=True)
    return errors


def apply_transaction(changes: list[Change]) -> None:
    staged: dict[pathlib.Path, pathlib.Path] = {}
    adopted: list[tuple[Change, os.stat_result]] = []
    try:
        # Validate/compute happened in build_changes(). Stage every private
        # replacement before changing any authoritative path.
        for change in changes:
            staged[change.path] = stage_private(change.path, change.after)

        for change in changes:
            require_owned_state(change.path, change.before_stat, "owned endpoint file")
            tmp = staged[change.path]
            os.replace(tmp, change.path)
            staged.pop(change.path, None)
            adopted_stat = change.path.lstat()
            if stat.S_ISLNK(adopted_stat.st_mode) or not stat.S_ISREG(adopted_stat.st_mode):
                raise RuntimeError(f"adopted endpoint file is unsafe: {change.path}")
            adopted.append((change, adopted_stat))
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
    # Keep the lexical path: resolving would hide a symlinked ancestor that the
    # owned-file boundary is specifically required to reject.
    base = pathlib.Path(os.path.abspath(base))
    _validate_owned_ancestors(base)
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
