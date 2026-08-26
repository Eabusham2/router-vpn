#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

BASE = Path(sys.argv[1] if len(sys.argv) > 1 else "/opt/router-vpn")
WG_CLIENT = BASE / "client-bundle" / "generated" / "wg" / "wg.conf"
AGENT_CONFIG = BASE / "config" / "router-agent.json"
PROOF_FILE = BASE / "config" / "node-proof-id"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
MAX_PRIVATE_BYTES = 4 << 20
PRIVATE_MODE = 0o600


def ensure_private_parent(path: Path, label: str) -> None:
    try:
        info = path.parent.lstat()
    except FileNotFoundError as exc:
        raise SystemExit(f"missing {label} parent: {path.parent}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise SystemExit(f"refusing non-directory/symlink {label} parent: {path.parent}")


def read_regular_text(path: Path, label: str) -> str:
    ensure_private_parent(path, label)
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise SystemExit(f"missing {label}: {path}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise SystemExit(f"refusing non-regular/symlink {label}: {path}")
    if info.st_mode & 0o777 != PRIVATE_MODE:
        raise SystemExit(f"{label} must be mode 0600: {path}")
    if info.st_size <= 0 or info.st_size > MAX_PRIVATE_BYTES:
        raise SystemExit(f"invalid/oversized {label}: {path}")

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        current = path.lstat()
        if stat.S_ISLNK(current.st_mode) or not stat.S_ISREG(current.st_mode) or not os.path.samestat(opened, current):
            raise SystemExit(f"{label} changed during open: {path}")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(64 * 1024, MAX_PRIVATE_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_PRIVATE_BYTES:
                raise SystemExit(f"invalid/oversized {label}: {path}")
        try:
            return b"".join(chunks).decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise SystemExit(f"{label} is not UTF-8: {path}") from exc
    finally:
        os.close(fd)


def peer_public_key(path: Path) -> str:
    peer = False
    for raw in read_regular_text(path, "WireGuard client profile").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            peer = line.lower() == "[peer]"
            continue
        if peer and "=" in line:
            key, value = (part.strip() for part in line.split("=", 1))
            if key.lower() == "publickey":
                if not value or len(value) > 128:
                    raise SystemExit("invalid WireGuard server public key in client profile")
                return value
    raise SystemExit("WireGuard server public key is missing from client profile")


def derive(public_key: str) -> str:
    return hashlib.sha256(("router-vpn-node-proof-v1\n" + public_key).encode()).hexdigest()


def main() -> int:
    public_key = peer_public_key(WG_CLIENT)
    node_id = derive(public_key)
    if not HEX64.fullmatch(node_id):
        raise SystemExit("derived node proof id is invalid")

    try:
        config = json.loads(read_regular_text(AGENT_CONFIG, "router-agent config"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"router-agent config is invalid JSON: {exc}") from exc
    if not isinstance(config, dict):
        raise SystemExit("router-agent config must be a JSON object")
    existing = str(config.get("node_id") or "").strip()
    if existing and existing != node_id:
        raise SystemExit("preserved router-agent node proof identity conflicts with WireGuard server identity")
    config["node_id"] = node_id

    helper = Path(__file__).with_name("atomic-private-batch.py")
    ensure_private_parent(AGENT_CONFIG, "router-agent config")
    tmp_dir = Path(tempfile.mkdtemp(prefix=".node-proof-", dir=AGENT_CONFIG.parent))
    try:
        config_tmp = tmp_dir / "router-agent.json"
        proof_tmp = tmp_dir / "node-proof-id"
        config_tmp.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
        proof_tmp.write_text(node_id + "\n", encoding="utf-8")
        os.chmod(config_tmp, 0o600)
        os.chmod(proof_tmp, 0o600)
        subprocess.run(
            [
                sys.executable,
                str(helper),
                f"{AGENT_CONFIG}={config_tmp}",
                f"{PROOF_FILE}={proof_tmp}",
            ],
            check=True,
        )
    finally:
        for child in tmp_dir.iterdir():
            child.unlink(missing_ok=True)
        tmp_dir.rmdir()
    print(node_id)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
