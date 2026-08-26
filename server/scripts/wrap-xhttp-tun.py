#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import pathlib
import stat
import subprocess
import sys
import tempfile

base = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "/opt/router-vpn")
dns = sys.argv[2] if len(sys.argv) > 2 else "10.77.0.1"
dir_ = base / "client-bundle" / "generated" / "reality-xhttp"
xray = dir_ / "xray.json"
try:
    info = xray.lstat()
except FileNotFoundError as exc:
    raise SystemExit("XHTTP Xray profile is missing") from exc
if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_size <= 0:
    raise SystemExit("XHTTP Xray profile is missing/unsafe")

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
body = (json.dumps(cfg, indent=2) + "\n").encode("utf-8")
fd, name = tempfile.mkstemp(prefix=".xhttp-wrapper-", suffix=".json", dir=dir_)
candidate = pathlib.Path(name)
try:
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "wb", closefd=True) as stream:
        stream.write(body)
        stream.flush()
        os.fsync(stream.fileno())
    # The finalizer image carries sing-box. Validation happens against disposable
    # staging so a rejected candidate never replaces the last working wrapper.
    subprocess.run(
        ["sing-box", "check", "-D", str(dir_), "-c", str(candidate)],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    helper = pathlib.Path(__file__).with_name("atomic-private-write.py")
    subprocess.run([sys.executable, str(helper), str(dir_ / "sing-box.json")], input=body, check=True)
finally:
    candidate.unlink(missing_ok=True)
print("validated XHTTP full-tunnel wrapper before atomic adoption")
