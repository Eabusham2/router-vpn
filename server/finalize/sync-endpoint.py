#!/usr/bin/env python3
from __future__ import annotations

import ipaddress
import json
import pathlib
import re
import sys

if len(sys.argv) != 3:
    raise SystemExit("usage: sync-endpoint.py BASE ENDPOINT")

base = pathlib.Path(sys.argv[1])
endpoint = sys.argv[2].strip().strip("[]")
if not endpoint or endpoint == "router.invalid":
    raise SystemExit("refusing to sync an empty/placeholder endpoint")

try:
    parsed = ipaddress.ip_address(endpoint)
    rendered = f"[{parsed}]" if parsed.version == 6 else str(parsed)
except ValueError:
    if not re.fullmatch(r"(?i)[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", endpoint):
        raise SystemExit("invalid endpoint")
    rendered = endpoint.lower()

# Endpoint sync owns only direct Router VPN WireGuard-family endpoint fields.
# It must never scan/replace arbitrary JSON server/address fields or rewrite a
# linked external node simply because it also has an `endpoint` property.
raw_profiles = {
    "wg": ("wg.conf", "wg-socks.conf"),
    "wg-pq": ("wg.conf", "wg-socks.conf"),
    "awg2-fast": ("awg.conf", "awg-socks.conf"),
    "awg2-strong": ("awg.conf", "awg-socks.conf"),
    "awg2-pq": ("awg.conf", "awg-socks.conf"),
}
endpoint_line = re.compile(r"(?m)^(\s*Endpoint\s*=\s*)(?:\[[^\]]+\]|[^:\s]+):(\d+)\s*$")
patched = 0
for mode, names in raw_profiles.items():
    for name in names:
        path = base / "client-bundle" / "generated" / mode / name
        if not path.is_file():
            continue
        text = path.read_text()
        updated, count = endpoint_line.subn(lambda m: f"{m.group(1)}{rendered}:{m.group(2)}", text)
        if count:
            path.write_text(updated)
            patched += 1

routers_path = base / "client-bundle" / "routers.json"
if routers_path.is_file():
    routers = json.loads(routers_path.read_text())
    profiles = routers.get("profiles", []) if isinstance(routers, dict) else []
    if isinstance(profiles, list):
        for profile in profiles:
            if not isinstance(profile, dict):
                continue
            # create-bundle-json.py owns exactly the local home Router VPN
            # profile. Other linked Router VPN nodes and all external nodes are
            # user/import data and are outside this server's endpoint authority.
            if str(profile.get("id") or "").strip() != "home":
                continue
            kind = str(profile.get("node_kind") or "router-vpn").strip().lower()
            if kind != "router-vpn":
                continue
            profile["endpoint"] = endpoint
    routers_path.write_text(json.dumps(routers, indent=2) + "\n")

if patched == 0:
    raise SystemExit("no raw WireGuard/AmneziaWG Endpoint lines were found")
print(f"Synced endpoint {endpoint} into {patched} raw tunnel profile files and the owned home Router VPN profile only.")
