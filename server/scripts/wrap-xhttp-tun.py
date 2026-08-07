#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys

base = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "/opt/router-vpn")
dns = sys.argv[2] if len(sys.argv) > 2 else "10.77.0.1"
dir_ = base / "client-bundle" / "generated" / "reality-xhttp"
xray = dir_ / "xray.json"
if not xray.is_file():
    raise SystemExit("XHTTP Xray profile is missing")

cfg = {
    "log": {"level": "warn"},
    "dns": {
        "servers": [
            {"type": "udp", "tag": "home-dns", "server": dns, "server_port": 53, "detour": "proxy"}
        ],
        "final": "home-dns",
    },
    "inbounds": [
        {
            "type": "tun",
            "tag": "tun-in",
            "interface_name": "router-vpn-xhttp",
            "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
            "mtu": 1320,
            "auto_route": True,
            "strict_route": True,
        }
    ],
    "outbounds": [
        {"type": "socks", "tag": "proxy", "server": "127.0.0.1", "server_port": 1090, "version": "5"},
        {"type": "direct", "tag": "direct"},
    ],
    "route": {
        "rules": [{"protocol": "dns", "action": "hijack-dns"}],
        "auto_detect_interface": True,
        "final": "proxy",
    },
}
out = dir_ / "sing-box.json"
out.write_text(json.dumps(cfg, indent=2) + "\n")
out.chmod(0o600)

# The finalizer image carries sing-box. Validate here so existence never means ready.
subprocess.run(["sing-box", "check", "-D", str(dir_), "-c", str(out)], check=True, stdout=subprocess.DEVNULL)
print("validated XHTTP full-tunnel wrapper")
