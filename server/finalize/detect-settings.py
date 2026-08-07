#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import shlex
import sys
from pathlib import Path

base = Path(sys.argv[1] if len(sys.argv) > 1 else "/opt/router-vpn")
values: dict[str, str | int] = {}


def load(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except Exception:
        return {}


def listen_port(path: Path) -> int | None:
    try:
        match = re.search(r"(?mi)^ListenPort\s*=\s*(\d+)\s*$", path.read_text())
        return int(match.group(1)) if match else None
    except OSError:
        return None

wg = listen_port(base / "config/wireguard/wg0.conf")
awg = listen_port(base / "config/awg2/awg0.conf")
if wg:
    values["WG_PORT"] = wg
if awg:
    values["AWG_PORT"] = awg

transports = load(base / "config/transports/server.json")
for inbound in transports.get("inbounds", []):
    tag = inbound.get("tag")
    port = inbound.get("listen_port")
    if not isinstance(port, int):
        continue
    # Backward compatibility: old installs stored REALITY in sing-box. New
    # installs overwrite REALITY_PORT below from Xray when that inbound exists.
    if tag == "reality-in":
        values["REALITY_PORT"] = port
    elif tag == "hy2-in":
        values["HY2_PORT"] = port
    elif tag == "ss-in":
        values["SS_PORT"] = port

xray = load(base / "config/xray/server.json")
for inbound in xray.get("inbounds", []):
    tag = inbound.get("tag")
    port = inbound.get("port")
    if not isinstance(port, int):
        continue
    if tag == "reality-in":
        values["REALITY_PORT"] = port
    elif tag == "pq-reality-in":
        values["XRAY_PQ_PORT"] = port
    elif tag == "max-xhttp-in":
        values["XHTTP_PORT"] = port

# TLS alternate generated metadata is the source of truth for those listener ports.
tls = load(base / "config/tls/generated.json")
if isinstance(tls.get("ss_v2ray_port"), int):
    values["SS_V2RAY_PORT"] = tls["ss_v2ray_port"]
if isinstance(tls.get("naive_port"), int):
    values["NAIVE_PORT"] = tls["naive_port"]

agent = load(base / "config/router-agent.json")
if agent.get("wan_interface"):
    values["WAN_INTERFACE"] = str(agent["wan_interface"])

routers = load(base / "client-bundle/routers.json")
profiles = routers.get("profiles", [])
selected_id = routers.get("selected_id")
profile = next((p for p in profiles if p.get("id") == selected_id), profiles[0] if profiles else {})
if profile.get("endpoint"):
    values["ENDPOINT"] = str(profile["endpoint"])
if profile.get("adguard_ipv4"):
    values["ADGUARD4"] = str(profile["adguard_ipv4"])

for key, value in values.items():
    print(f"{key}={shlex.quote(str(value))}")
