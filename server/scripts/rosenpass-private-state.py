#!/usr/bin/env python3
"""Verify/preserve Rosenpass identity without pathname-following races."""
from __future__ import annotations

import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys
import tempfile

MAX_PRIVATE_BYTES = 4 << 20
PRIVATE_MODE = 0o600


def _validate_existing_ancestors(parent: Path, label: str) -> None:
    for current in (parent, *parent.parents):
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise RuntimeError(f"refusing non-directory/symlink {label} path component: {current}")


def ensure_parent(path: Path, label: str) -> None:
    _validate_existing_ancestors(path.parent, label)
    info = path.parent.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise RuntimeError(f"refusing non-directory/symlink {label} parent: {path.parent}")
    _validate_existing_ancestors(path.parent, label)


def read_private(path: Path, label: str) -> bytes:
    ensure_parent(path, label)
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise RuntimeError(f"refusing non-regular/symlink {label}: {path}")
    if info.st_mode & 0o777 != PRIVATE_MODE:
        raise RuntimeError(f"{label} must be mode 0600: {path}")
    if info.st_size <= 0 or info.st_size > MAX_PRIVATE_BYTES:
        raise RuntimeError(f"{label} is empty or oversized: {path}")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(fd)
        current = path.lstat()
        if stat.S_ISLNK(current.st_mode) or not stat.S_ISREG(current.st_mode) or not os.path.samestat(opened, current):
            raise RuntimeError(f"{label} changed during open: {path}")
        out = bytearray()
        while True:
            chunk = os.read(fd, min(64 * 1024, MAX_PRIVATE_BYTES + 1 - len(out)))
            if not chunk:
                break
            out.extend(chunk)
            if len(out) > MAX_PRIVATE_BYTES:
                raise RuntimeError(f"{label} is oversized: {path}")
        ensure_parent(path, label)
        current = path.lstat()
        if stat.S_ISLNK(current.st_mode) or not stat.S_ISREG(current.st_mode) or not os.path.samestat(opened, current):
            raise RuntimeError(f"{label} changed during read: {path}")
        return bytes(out)
    finally:
        os.close(fd)


def read_text(path: Path, label: str) -> str:
    try:
        return read_private(path, label).decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise RuntimeError(f"{label} is not UTF-8: {path}") from exc


def paths(base: Path) -> dict[str, Path]:
    server = base / "config" / "rosenpass"
    wg = base / "client-bundle" / "generated" / "wg-pq"
    awg = base / "client-bundle" / "generated" / "awg2-pq"
    return {
        "server_public": server / "server-public",
        "server_secret": server / "server-secret",
        "wg_server_peer": server / "wg-client-public",
        "awg_server_peer": server / "awg-client-public",
        "server_toml": server / "server.toml",
        "server_env": server / "server.env",
        "wg_secret": wg / "rosenpass-client-secret",
        "wg_public": wg / "rosenpass-client-public",
        "wg_server_public": wg / "rosenpass-server-public",
        "wg_toml": wg / "rosenpass.toml",
        "wg_env": wg / "rosenpass.env",
        "awg_secret": awg / "rosenpass-client-secret",
        "awg_public": awg / "rosenpass-client-public",
        "awg_server_public": awg / "rosenpass-server-public",
        "awg_toml": awg / "rosenpass.toml",
        "awg_env": awg / "rosenpass.env",
    }


def family_presence(items: dict[str, Path]) -> tuple[bool, bool]:
    present = []
    for path in items.values():
        _validate_existing_ancestors(path.parent, "Rosenpass identity")
        try:
            path.lstat()
            present.append(True)
        except FileNotFoundError:
            present.append(False)
    return any(present), all(present)


def verify_existing(base: Path) -> dict[str, bytes] | None:
    items = paths(base)
    any_present, all_present = family_presence(items)
    if not any_present:
        return None
    if not all_present:
        missing = [str(path) for path in items.values() if not path.exists()]
        raise RuntimeError("existing Rosenpass identity is partial/unsafe; refusing silent key rotation: " + ", ".join(missing))
    values = {name: read_private(path, f"Rosenpass {name}") for name, path in items.items()}
    if values["server_public"] != values["wg_server_public"]:
        raise RuntimeError("WG-PQ Rosenpass server public key disagrees with preserved server identity")
    if values["server_public"] != values["awg_server_public"]:
        raise RuntimeError("AWG-PQ Rosenpass server public key disagrees with preserved server identity")
    if values["wg_server_peer"] != values["wg_public"]:
        raise RuntimeError("WG-PQ Rosenpass client public key disagrees with preserved server peer identity")
    if values["awg_server_peer"] != values["awg_public"]:
        raise RuntimeError("AWG-PQ Rosenpass client public key disagrees with preserved server peer identity")
    return values


def refresh_existing(base: Path, endpoint: str, port: int) -> None:
    values = verify_existing(base)
    if values is None:
        raise RuntimeError("Rosenpass identity is absent")
    if not 1 <= port <= 65535:
        raise RuntimeError("invalid Rosenpass port")
    if not endpoint or any(ch in endpoint for ch in "\r\n\x00\"'"):
        raise RuntimeError("invalid Rosenpass endpoint")
    items = paths(base)
    wg_env = values["wg_env"].decode("utf-8", errors="strict")
    awg_env = values["awg_env"].decode("utf-8", errors="strict")
    wg_toml = values["wg_toml"].decode("utf-8", errors="strict")
    awg_toml = values["awg_toml"].decode("utf-8", errors="strict")
    wg_env, wg_count = re.subn(r"(?m)^ROSENPASS_INTERFACE=.*$", "ROSENPASS_INTERFACE=wg", wg_env)
    awg_env, awg_count = re.subn(r"(?m)^ROSENPASS_INTERFACE=.*$", "ROSENPASS_INTERFACE=awg", awg_env)
    replacement = f'endpoint = "{endpoint}:{port}"'
    wg_toml, wg_toml_count = re.subn(r"(?m)^endpoint\s*=.*$", replacement, wg_toml)
    awg_toml, awg_toml_count = re.subn(r"(?m)^endpoint\s*=.*$", replacement, awg_toml)
    if (wg_count, awg_count, wg_toml_count, awg_toml_count) != (1, 1, 1, 1):
        raise RuntimeError("preserved Rosenpass metadata has ambiguous/missing owned fields")

    helper = Path(__file__).with_name("atomic-private-batch.py")
    server_dir = base / "config" / "rosenpass"
    ensure_parent(items["server_public"], "Rosenpass server state")
    tmp_dir = Path(tempfile.mkdtemp(prefix=".repair.", dir=server_dir))
    try:
        staged = {
            "wg.env": wg_env.encode(),
            "awg.env": awg_env.encode(),
            "wg.toml": wg_toml.encode(),
            "awg.toml": awg_toml.encode(),
        }
        for name, body in staged.items():
            path = tmp_dir / name
            path.write_bytes(body)
            os.chmod(path, PRIVATE_MODE)
        subprocess.run(
            [
                sys.executable,
                str(helper),
                f"{items['wg_env']}={tmp_dir / 'wg.env'}",
                f"{items['awg_env']}={tmp_dir / 'awg.env'}",
                f"{items['wg_toml']}={tmp_dir / 'wg.toml'}",
                f"{items['awg_toml']}={tmp_dir / 'awg.toml'}",
            ],
            check=True,
        )
    finally:
        for child in tmp_dir.iterdir():
            child.unlink(missing_ok=True)
        tmp_dir.rmdir()


def parse_config_value(text: str, section: str, key: str) -> str:
    current = ""
    found: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1]
            continue
        if current == section and "=" in line:
            k, value = line.split("=", 1)
            if k.strip() == key:
                found.append(value.strip())
    if len(found) != 1 or not found[0] or any(ch in found[0] for ch in "\r\n\x00"):
        raise RuntimeError(f"expected exactly one {section}.{key}")
    return found[0]


def base_key_assignments(base: Path) -> dict[str, str]:
    wg = read_text(base / "config" / "wireguard" / "wg0.conf", "WireGuard server config")
    awg = read_text(base / "config" / "awg2" / "awg0.conf", "AmneziaWG server config")
    return {
        "WG_SERVER_PRIV": parse_config_value(wg, "Interface", "PrivateKey"),
        "WG_CLIENT_PUB": parse_config_value(wg, "Peer", "PublicKey"),
        "AWG_SERVER_PRIV": parse_config_value(awg, "Interface", "PrivateKey"),
        "AWG_CLIENT_PUB": parse_config_value(awg, "Peer", "PublicKey"),
    }


def emit_assignments(values: dict[str, str]) -> None:
    for key, value in values.items():
        print(f"{key}={shlex.quote(value)}")


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print("usage: rosenpass-private-state.py probe|refresh|base-keys BASE [ENDPOINT PORT]", file=sys.stderr)
        return 2
    action = argv[1]
    base = Path(argv[2])
    try:
        if action == "probe":
            print("present" if verify_existing(base) is not None else "absent")
        elif action == "refresh" and len(argv) == 5:
            refresh_existing(base, argv[3], int(argv[4]))
        elif action == "base-keys" and len(argv) == 3:
            emit_assignments(base_key_assignments(base))
        else:
            return 2
    except (OSError, RuntimeError, subprocess.CalledProcessError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
