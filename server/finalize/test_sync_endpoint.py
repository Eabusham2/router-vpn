#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile

SCRIPT = Path(__file__).with_name("sync-endpoint.py")

with tempfile.TemporaryDirectory(prefix="router-vpn-sync-endpoint-") as td:
    base = Path(td)
    wg = base / "client-bundle" / "generated" / "wg"
    wg.mkdir(parents=True)
    (wg / "wg.conf").write_text("[Peer]\nEndpoint = old.example:51820\n")
    routers_path = base / "client-bundle" / "routers.json"
    original = {
        "schema_version": 4,
        "selected_id": "home",
        "profiles": [
            {"id": "home", "node_kind": "router-vpn", "endpoint": "old.example"},
            {"id": "other-router", "node_kind": "router-vpn", "endpoint": "other.example"},
            {
                "id": "external-exit",
                "node_kind": "external",
                "endpoint": "exit.example",
                "external": {"shadowsocks": {"server": "ss.example", "port": 8388}},
            },
        ],
    }
    routers_path.write_text(json.dumps(original))

    subprocess.run([sys.executable, str(SCRIPT), str(base), "203.0.113.9"], check=True)

    assert "Endpoint = 203.0.113.9:51820" in (wg / "wg.conf").read_text()
    updated = json.loads(routers_path.read_text())
    profiles = {p["id"]: p for p in updated["profiles"]}
    assert profiles["home"]["endpoint"] == "203.0.113.9"
    assert profiles["other-router"]["endpoint"] == "other.example"
    assert profiles["external-exit"]["endpoint"] == "exit.example"
    assert profiles["external-exit"]["external"]["shadowsocks"]["server"] == "ss.example"

print("endpoint sync ownership test: PASS")
