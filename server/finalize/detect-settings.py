#!/usr/bin/env python3
from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import stat
import sys
from typing import Any

MAX_STATE_BYTES = 4 << 20
base = Path(os.path.abspath(os.path.expanduser(sys.argv[1] if len(sys.argv) > 1 else "/opt/router-vpn")))
values: dict[str, str | int] = {}


def validate_ancestors(path: Path) -> None:
    current = path.parent
    while True:
        try:
            info = current.lstat()
        except FileNotFoundError:
            pass
        else:
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise RuntimeError(f"refusing non-directory/symlink Router VPN state path component: {current}")
        parent = current.parent
        if parent == current:
            break
        current = parent


def private_text(path: Path, *, optional: bool = True) -> str | None:
    validate_ancestors(path)
    try:
        before = path.lstat()
    except FileNotFoundError:
        if optional:
            return None
        raise RuntimeError(f"required Router VPN state is missing: {path}")
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise RuntimeError(f"refusing non-regular/symlink Router VPN state: {path}")
    if before.st_size < 0 or before.st_size > MAX_STATE_BYTES:
        raise RuntimeError(f"Router VPN state exceeds safety limit: {path}")

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb", closefd=True) as stream:
        opened = os.fstat(stream.fileno())
        current = path.lstat()
        if (
            stat.S_ISLNK(current.st_mode)
            or not stat.S_ISREG(current.st_mode)
            or not os.path.samestat(opened, current)
        ):
            raise RuntimeError(f"Router VPN state changed during open: {path}")
        if os.name != "nt" and opened.st_mode & 0o077:
            os.fchmod(stream.fileno(), 0o600)
        raw = stream.read(MAX_STATE_BYTES + 1)
    if len(raw) > MAX_STATE_BYTES:
        raise RuntimeError(f"Router VPN state exceeds safety limit: {path}")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RuntimeError(f"Router VPN state is not UTF-8: {path}") from exc


def load(path: Path, *, optional: bool = True) -> dict[str, Any]:
    text = private_text(path, optional=optional)
    if text is None:
        return {}
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"corrupt Router VPN JSON state: {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise RuntimeError(f"Router VPN JSON state must be an object: {path}")
    return value


def listen_port(path: Path) -> int | None:
    text = private_text(path)
    if text is None:
        return None
    match = re.search(r"(?mi)^ListenPort\s*=\s*(\d+)\s*$", text)
    if not match:
        raise RuntimeError(f"existing tunnel config has no valid ListenPort: {path}")
    port = int(match.group(1))
    if not 1 <= port <= 65535:
        raise RuntimeError(f"existing tunnel config has invalid ListenPort: {path}")
    return port


def set_port(key: str, value: Any) -> None:
    if not isinstance(value, int) or not 1 <= value <= 65535:
        raise RuntimeError(f"invalid preserved {key}: {value!r}")
    values[key] = value


wg = listen_port(base / "config/wireguard/wg0.conf")
awg = listen_port(base / "config/awg2/awg0.conf")
if wg:
    values["WG_PORT"] = wg
if awg:
    values["AWG_PORT"] = awg

transports = load(base / "config/transports/server.json")
for inbound in transports.get("inbounds", []):
    if not isinstance(inbound, dict):
        continue
    tag = inbound.get("tag")
    port = inbound.get("listen_port")
    if tag == "reality-in":
        set_port("REALITY_PORT", port)
    elif tag == "hy2-in":
        set_port("HY2_PORT", port)
    elif tag == "ss-in":
        set_port("SS_PORT", port)

xray = load(base / "config/xray/server.json")
for inbound in xray.get("inbounds", []):
    if not isinstance(inbound, dict):
        continue
    tag = inbound.get("tag")
    port = inbound.get("port")
    if tag == "reality-in":
        set_port("REALITY_PORT", port)
    elif tag == "pq-reality-in":
        set_port("XRAY_PQ_PORT", port)
    elif tag == "max-xhttp-in":
        set_port("XHTTP_PORT", port)

tls = load(base / "config/tls/generated.json")
if "ss_v2ray_port" in tls:
    set_port("SS_V2RAY_PORT", tls["ss_v2ray_port"])
if "naive_port" in tls:
    set_port("NAIVE_PORT", tls["naive_port"])

agent = load(base / "config/router-agent.json", optional=False)
wan = str(agent.get("wan_interface") or "").strip()
if wan:
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", wan):
        raise RuntimeError("preserved WAN interface is invalid")
    values["WAN_INTERFACE"] = wan

routers = load(base / "client-bundle/routers.json", optional=False)
profiles = [p for p in routers.get("profiles", []) if isinstance(p, dict)]
selected_id = str(routers.get("selected_id") or "").strip()
if not selected_id:
    raise RuntimeError("preserved Router VPN profile store has no selected_id")
matches = [p for p in profiles if str(p.get("id") or "") == selected_id]
if len(matches) != 1:
    raise RuntimeError(f"expected one preserved selected Router VPN profile {selected_id!r}, found {len(matches)}")
profile = matches[0]

endpoint = str(profile.get("endpoint") or "").strip()
if endpoint:
    if "\n" in endpoint or "\r" in endpoint or "\x00" in endpoint or len(endpoint) > 255:
        raise RuntimeError("preserved Router VPN endpoint is invalid")
    values["ENDPOINT"] = endpoint

adguard = str(profile.get("adguard_ipv4") or "").strip()
if adguard:
    try:
        parsed = ipaddress.ip_address(adguard.strip("[]"))
    except ValueError as exc:
        raise RuntimeError("preserved AdGuard IPv4 is invalid") from exc
    if parsed.version != 4:
        raise RuntimeError("preserved AdGuard IPv4 is not IPv4")
    values["ADGUARD4"] = str(parsed)

for key, value in values.items():
    print(f"{key}={shlex.quote(str(value))}")
