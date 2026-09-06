#!/usr/bin/env python3
from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
import shlex
import stat
import sys
import tempfile

from private_profile_store import private_root, read_profile_store
from profile_id import validate_profile_id

AES = "aes-256-gcm"
AES_XOR = "aes-256-gcm+xor-whitening"
AES_METHOD = "2022-blake3-aes-256-gcm"
START_TAG = "start-layer-aes"
XOR_LISTEN = "127.0.0.1:18389"
XOR_PORT = 8389
SS_PORT = 8388
SUPPORTED = {"shadowsocks", "hysteria2", "naive-h2", "naive-h3"}
MAX_JSON = 4 << 20


def normalize(value: object) -> str:
    raw = str(value or "").strip().lower().replace("_", "-").replace(" ", "")
    if raw in {"", "off", "none", "disabled"}:
        return "off"
    if raw in {"aes", "aes256", "aes-256", "aes-gcm", "aes256-gcm", AES}:
        return AES
    if raw in {"aes+xor", "xor+aes", "aes-256-gcm+xor", "xor+aes-256-gcm", AES_XOR}:
        return AES_XOR
    if raw in {"xor", "xor-only", "xor-whitening"}:
        raise RuntimeError("XOR whitening is obfuscation only and requires AES-256-GCM")
    raise RuntimeError(f"unsupported start layer {raw!r}")


def profile(root: Path, profile_id: str) -> dict:
    store = read_profile_store(root)
    for row in store.get("profiles", []):
        if isinstance(row, dict) and str(row.get("id") or "") == profile_id:
            return row
    raise RuntimeError(f"Router VPN profile {profile_id!r} is missing")


def read_json(path: Path) -> dict:
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or before.st_size <= 0 or before.st_size > MAX_JSON:
        raise RuntimeError(f"unsafe start-layer JSON: {path}")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(fd)
        current = path.lstat()
        if stat.S_ISLNK(current.st_mode) or not stat.S_ISREG(current.st_mode) or not os.path.samestat(opened, current) or not os.path.samestat(opened, before):
            raise RuntimeError(f"start-layer JSON changed during open: {path}")
        body = b""
        while len(body) <= MAX_JSON:
            chunk = os.read(fd, min(65536, MAX_JSON + 1 - len(body)))
            if not chunk:
                break
            body += chunk
        if len(body) > MAX_JSON:
            raise RuntimeError(f"start-layer JSON exceeds safety limit: {path}")
        final = path.lstat()
        if stat.S_ISLNK(final.st_mode) or not stat.S_ISREG(final.st_mode) or not os.path.samestat(opened, final):
            raise RuntimeError(f"start-layer JSON changed during read: {path}")
    finally:
        os.close(fd)
    value = json.loads(body.decode("utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"start-layer JSON root is not an object: {path}")
    return value


def atomic_json(path: Path, value: dict) -> None:
    parent = path.parent
    parent_info = parent.lstat()
    if stat.S_ISLNK(parent_info.st_mode) or not stat.S_ISDIR(parent_info.st_mode):
        raise RuntimeError(f"unsafe start-layer output directory: {parent}")
    if path.exists() or path.is_symlink():
        current = path.lstat()
        if stat.S_ISLNK(current.st_mode) or not stat.S_ISREG(current.st_mode):
            raise RuntimeError(f"unsafe start-layer output target: {path}")
    body = (json.dumps(value, indent=2) + "\n").encode()
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.start-layer-", dir=parent)
    tmp = Path(name)
    committed = False
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
        after_parent = parent.lstat()
        if stat.S_ISLNK(after_parent.st_mode) or not stat.S_ISDIR(after_parent.st_mode) or not os.path.samestat(parent_info, after_parent):
            raise RuntimeError(f"start-layer output directory changed before adoption: {parent}")
        if path.exists() or path.is_symlink():
            current = path.lstat()
            if stat.S_ISLNK(current.st_mode) or not stat.S_ISREG(current.st_mode):
                raise RuntimeError(f"start-layer output target changed type before adoption: {path}")
        os.replace(tmp, path)
        committed = True
        try:
            dfd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        except OSError:
            pass
    finally:
        if not committed:
            try:
                os.close(fd)
            except OSError:
                pass
            tmp.unlink(missing_ok=True)


def endpoint_host(value: str) -> str:
    host = value.strip().strip("[]")
    if not host or any(ch in host for ch in "\r\n\x00"):
        raise RuntimeError("start-layer endpoint is invalid")
    return host


def endpoint_hostport(value: str, port: int) -> str:
    host = endpoint_host(value)
    try:
        if ipaddress.ip_address(host).version == 6:
            return f"[{host}]:{port}"
    except ValueError:
        if any(ch in host for ch in " /\\?#@"):
            raise RuntimeError("start-layer endpoint host is unsafe")
    return f"{host}:{port}"


def ss_source(root: Path, profile_id: str) -> Path:
    for path in (root / "generated" / profile_id / "shadowsocks" / "sing-box.json",
                 root / "generated" / "shadowsocks" / "sing-box.json"):
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode):
            return path
    raise RuntimeError("generated Shadowsocks 2022 AES profile is missing")


def aes_outbound(path: Path) -> dict:
    doc = read_json(path)
    rows = doc.get("outbounds")
    if not isinstance(rows, list):
        raise RuntimeError("Shadowsocks profile has no outbounds")
    matches = [dict(row) for row in rows if isinstance(row, dict) and str(row.get("type") or "").lower() == "shadowsocks"]
    if len(matches) != 1:
        raise RuntimeError("AES start layer requires exactly one Shadowsocks outbound")
    row = matches[0]
    if str(row.get("method") or "").lower() != AES_METHOD or not str(row.get("password") or ""):
        raise RuntimeError("AES start layer requires authenticated Shadowsocks 2022 AES-256-GCM")
    return row


def prepare(root_text: str, profile_id: str, mode: str, conf_text: str, endpoint: str) -> dict:
    root = private_root(root_text)
    profile_id = validate_profile_id(profile_id)
    row = profile(root, profile_id)
    start = normalize(row.get("start_layer"))
    state = {"active": start, "xor": False}
    conf = Path(conf_text).resolve(strict=True)
    if start == "off":
        atomic_json(conf / "start-layer.json", state)
        return state
    if str(row.get("node_kind") or "router-vpn").lower() != "router-vpn":
        raise RuntimeError("start layer currently supports Router VPN home nodes only")
    if mode not in SUPPORTED:
        raise RuntimeError(f"{mode} does not yet have a proved start-layer composition path")

    remote_host = endpoint_host(endpoint)
    cfg_path = conf / "sing-box.json"
    target = read_json(cfg_path)
    outbounds = target.get("outbounds")
    if not isinstance(outbounds, list):
        raise RuntimeError(f"{mode} has no sing-box outbounds")
    xor = start == AES_XOR
    key_path = ss_source(root, profile_id)

    if mode == "shadowsocks":
        matches = [r for r in outbounds if isinstance(r, dict) and str(r.get("type") or "").lower() == "shadowsocks"]
        if len(matches) != 1 or str(matches[0].get("method") or "").lower() != AES_METHOD:
            raise RuntimeError("selected Shadowsocks mode is not AES-256-GCM")
        if xor:
            matches[0]["server"] = "127.0.0.1"
            matches[0]["server_port"] = 18389
    else:
        aes = aes_outbound(key_path)
        aes["tag"] = START_TAG
        aes["server"] = "127.0.0.1" if xor else remote_host
        aes["server_port"] = 18389 if xor else SS_PORT
        candidates = [r for r in outbounds if isinstance(r, dict) and r.get("tag") == "proxy"]
        if len(candidates) != 1 or candidates[0].get("detour") not in (None, ""):
            raise RuntimeError(f"{mode} does not expose one unowned proxy outbound")
        # The inner service lives on the same home node. The Shadowsocks server
        # resolves/dials this loopback destination after decrypting the outer hop.
        candidates[0]["server"] = "127.0.0.1"
        candidates[0]["detour"] = START_TAG
        outbounds.append(aes)

    atomic_json(cfg_path, target)
    state.update({
        "xor": xor,
        "key_config": str(key_path),
        "relay_listen": XOR_LISTEN if xor else "",
        "relay_target": endpoint_hostport(endpoint, XOR_PORT) if xor else "",
    })
    atomic_json(conf / "start-layer.json", state)
    return state


def emit_env(path: str) -> None:
    state = read_json(Path(path))
    values = {
        "HOMEVPN_START_LAYER": str(state.get("active") or "off"),
        "HOMEVPN_START_LAYER_XOR": "1" if state.get("xor") else "0",
        "HOMEVPN_START_LAYER_KEY_CONFIG": str(state.get("key_config") or ""),
        "HOMEVPN_START_LAYER_RELAY_LISTEN": str(state.get("relay_listen") or ""),
        "HOMEVPN_START_LAYER_RELAY_TARGET": str(state.get("relay_target") or ""),
    }
    for key, value in values.items():
        print(f"export {key}={shlex.quote(value)}")


def main(argv: list[str]) -> int:
    try:
        if len(argv) == 7 and argv[1] == "prepare":
            print(json.dumps(prepare(argv[2], argv[3], argv[4], argv[5], argv[6]), sort_keys=True))
            return 0
        if len(argv) == 3 and argv[1] == "env":
            emit_env(argv[2])
            return 0
        raise RuntimeError("usage: start-layer.py prepare ROOT PROFILE_ID MODE CONF ENDPOINT | env STATE_JSON")
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        print(f"start-layer error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
