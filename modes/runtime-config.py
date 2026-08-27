#!/usr/bin/env python3
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile

MAX_BYTES = 16 << 20


def trusted_path(root_text: str, path_text: str, *, must_exist: bool = False) -> tuple[Path, os.stat_result]:
    root = Path(root_text).resolve(strict=True)
    run = root / "run"
    run_info = run.lstat()
    if stat.S_ISLNK(run_info.st_mode) or not stat.S_ISDIR(run_info.st_mode):
        raise RuntimeError(f"refusing non-directory/symlink runtime directory: {run}")
    path = Path(path_text)
    if not path.is_absolute():
        path = root / path
    path = Path(os.path.abspath(path))
    try:
        rel_parent = path.parent.relative_to(run)
    except ValueError as exc:
        raise RuntimeError("runtime config path must stay under HOMEVPN_ROOT/run") from exc
    current = run
    for part in rel_parent.parts:
        current = current / part
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise RuntimeError(f"refusing non-directory/symlink runtime config ancestor: {current}")
    if must_exist:
        validate_target(path)
    return path, path.parent.lstat()


def validate_target(path: Path) -> os.stat_result:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise RuntimeError(f"refusing non-regular/symlink runtime config target: {path}")
    if info.st_size < 0 or info.st_size > MAX_BYTES:
        raise RuntimeError(f"runtime config exceeds safety limit: {path}")
    return info


def read_bytes(root: str, path_text: str) -> tuple[Path, bytes]:
    path, _ = trusted_path(root, path_text, must_exist=True)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        current = path.lstat()
        if stat.S_ISLNK(current.st_mode) or not stat.S_ISREG(current.st_mode) or not os.path.samestat(opened, current):
            raise RuntimeError(f"runtime config changed during open: {path}")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(1 << 20, MAX_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_BYTES:
                raise RuntimeError(f"runtime config exceeds safety limit: {path}")
        return path, b"".join(chunks)
    finally:
        os.close(fd)


def atomic_write(root: str, path_text: str, body: bytes) -> Path:
    if len(body) > MAX_BYTES:
        raise RuntimeError("runtime config output exceeds safety limit")
    path, parent_before = trusted_path(root, path_text)
    try:
        current = path.lstat()
    except FileNotFoundError:
        current = None
    if current is not None and (stat.S_ISLNK(current.st_mode) or not stat.S_ISREG(current.st_mode)):
        raise RuntimeError(f"refusing non-regular/symlink runtime config target: {path}")
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.runtime-", dir=path.parent)
    tmp = Path(name)
    committed = False
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=True) as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
        path_now, parent_now = trusted_path(root, path_text)
        if path_now != path or not os.path.samestat(parent_before, parent_now):
            raise RuntimeError("runtime config parent changed before adoption")
        try:
            target = path.lstat()
        except FileNotFoundError:
            target = None
        if target is not None and (stat.S_ISLNK(target.st_mode) or not stat.S_ISREG(target.st_mode)):
            raise RuntimeError("runtime config target changed before adoption")
        if current is None:
            if target is not None:
                raise RuntimeError("runtime config target appeared before adoption")
        elif target is None or not os.path.samestat(current, target):
            raise RuntimeError("runtime config target identity changed before adoption")
        os.replace(tmp, path)
        committed = True
        try:
            dfd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        except OSError:
            pass
        return path
    finally:
        if not committed:
            tmp.unlink(missing_ok=True)


def load_json(root: str, path: str) -> tuple[Path, dict]:
    resolved, body = read_bytes(root, path)
    value = json.loads(body.decode("utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError("runtime JSON config must be an object")
    return resolved, value


def dump_json(root: str, path: str, value: dict) -> Path:
    return atomic_write(root, path, (json.dumps(value, indent=2) + "\n").encode("utf-8"))


def patch_kernel_dns(root: str, path: str) -> None:
    resolved, body = read_bytes(root, path)
    text = body.decode("utf-8")
    if "[Interface]" not in text:
        raise RuntimeError("kernel tunnel config has no Interface section")
    if re.search(r"(?mi)^DNS\s*=", text):
        text = re.sub(r"(?mi)^DNS\s*=.*$", "DNS = 127.0.0.1", text)
    else:
        text = text.replace("[Interface]\n", "[Interface]\nDNS = 127.0.0.1\n", 1)
    atomic_write(root, str(resolved), text.encode("utf-8"))


def patch_rosenpass(root: str, path: str, endpoint: str, port_text: str) -> None:
    resolved, body = read_bytes(root, path)
    endpoint = endpoint.strip().strip("[]")
    try:
        port = int(port_text)
    except ValueError as exc:
        raise RuntimeError("invalid Rosenpass port") from exc
    if not endpoint or any(ch in endpoint for ch in "\r\n\x00") or not 1 <= port <= 65535:
        raise RuntimeError("invalid Rosenpass endpoint")
    host = f"[{endpoint}]" if ":" in endpoint else endpoint
    text = body.decode("utf-8")
    updated, count = re.subn(
        r"(?m)^endpoint\s*=\s*[\"'][^\"']*[\"']\s*$",
        f'endpoint = "{host}:{port}"',
        text,
    )
    if count != 1:
        raise RuntimeError("Rosenpass config must contain exactly one endpoint")
    atomic_write(root, str(resolved), updated.encode("utf-8"))


def sslocal_endpoint(root: str, path: str, endpoint: str) -> None:
    resolved, value = load_json(root, path)
    endpoint = endpoint.strip().strip("[]")
    if not endpoint or any(ch in endpoint for ch in "\r\n\x00"):
        raise RuntimeError("invalid SS+V2Ray endpoint")
    value["server"] = endpoint
    dump_json(root, str(resolved), value)


def sslocal_socks(root: str, source: str, target: str) -> None:
    _resolved, value = load_json(root, source)
    value["local_port"] = 1080
    dump_json(root, target, value)


def sing_variant(root: str, source: str, target: str, kind: str) -> None:
    _resolved, value = load_json(root, source)
    if kind == "socks":
        value["inbounds"] = [{"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 1080, "users": []}]
    elif kind == "jumbo":
        changed = False
        for inbound in value.get("inbounds", []):
            if isinstance(inbound, dict) and inbound.get("type") == "tun":
                inbound["mtu"] = 9000
                changed = True
        if not changed:
            raise RuntimeError("Jumbo runtime config has no TUN inbound")
    else:
        raise RuntimeError("runtime sing-box variant must be socks or jumbo")
    dump_json(root, target, value)


def local_socks(root: str, target: str, host: str, port_text: str) -> None:
    try:
        port = int(port_text)
    except ValueError as exc:
        raise RuntimeError("invalid private SOCKS port") from exc
    host = host.strip().strip("[]")
    if not host or any(ch in host for ch in "\r\n\x00") or not 1 <= port <= 65535:
        raise RuntimeError("invalid private SOCKS endpoint")
    cfg = {
        "log": {"level": "warn"},
        "inbounds": [{"type": "socks", "tag": "local-socks", "listen": "127.0.0.1", "listen_port": 1080, "users": []}],
        "outbounds": [{"type": "socks", "tag": "home-socks", "server": host, "server_port": port, "version": "5"}],
        "route": {"final": "home-socks"},
    }
    dump_json(root, target, cfg)


def dns_hint(root: str, target: str, mode: str, protocol: str, host: str, port: str) -> None:
    for value in (mode, protocol, host, port):
        if any(ch in value for ch in "\r\n\x00"):
            raise RuntimeError("invalid DNS hint value")
    atomic_write(root, target, f"mode={mode}\nprotocol={protocol}\nserver={host}:{port}\n".encode())


def main(argv: list[str]) -> int:
    try:
        cmd = argv[1] if len(argv) > 1 else ""
        if cmd == "patch-kernel-dns" and len(argv) == 4:
            patch_kernel_dns(argv[2], argv[3])
        elif cmd == "patch-rosenpass" and len(argv) == 6:
            patch_rosenpass(argv[2], argv[3], argv[4], argv[5])
        elif cmd == "sslocal-endpoint" and len(argv) == 5:
            sslocal_endpoint(argv[2], argv[3], argv[4])
        elif cmd == "sslocal-socks" and len(argv) == 5:
            sslocal_socks(argv[2], argv[3], argv[4])
        elif cmd == "sing-variant" and len(argv) == 6:
            sing_variant(argv[2], argv[3], argv[4], argv[5])
        elif cmd == "local-socks" and len(argv) == 6:
            local_socks(argv[2], argv[3], argv[4], argv[5])
        elif cmd == "dns-hint" and len(argv) == 8:
            dns_hint(argv[2], argv[3], argv[4], argv[5], argv[6], argv[7])
        else:
            raise RuntimeError("invalid runtime-config command")
        return 0
    except (OSError, RuntimeError, UnicodeError, json.JSONDecodeError) as exc:
        print(f"runtime config error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
