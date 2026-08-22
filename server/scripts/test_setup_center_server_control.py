#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]

def text(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")

control = text("cmd/router-agent/admin_server_control.go")
ui = text("server/scripts/setup_center_server_control.py")
product = text("server/scripts/setup-center-product-server.py")
reserved = text("cmd/router-agent/reserved_dynamic.go")

for marker in (
    'defaultAdminServerControlListen = "127.0.0.1:8792"',
    'subtle.ConstantTimeCompare',
    '/api/admin/server-control/stop',
    '/api/admin/server-control/emergency-stop',
    '/api/admin/server-control/resume',
    'serverControlInfrastructurePorts',
    'router-vpn server paused',
    'removeLivePeer(peer.Interface, peer.PublicKey)',
    'Resume restores ingress without rotating keys or deleting configuration',
):
    assert marker in control, f"server control missing {marker!r}"

for forbidden in (
    'docker system prune', 'docker stop', 'docker rm', '/var/run/docker.sock',
    '0.0.0.0:8792', 'policy drop', 'flush ruleset',
):
    assert forbidden not in control, f"server control contains unsafe marker {forbidden!r}"

for marker in (
    'Stop VPN', 'Emergency Stop', 'Resume VPN',
    '/api/admin/server-control/stop',
    '/api/admin/server-control/emergency-stop',
    '/api/admin/server-control/resume',
    "credentials:'same-origin'",
):
    assert marker in ui, f"Setup Center server-control UI missing {marker!r}"

for marker in (
    'SERVER_CONTROL_BASE = "http://127.0.0.1:8792"',
    'SERVER_CONTROL_PREFIX = "/api/admin/server-control"',
    '_proxy_server_control',
    '_require_auth()',
    'setup_center_server_control.py',
):
    assert marker in product, f"Setup Center product proxy missing {marker!r}"

for port in (8791, 8792, 8793, 18080):
    assert f"{port}," in reserved, f"protected control/internal port {port} is not permanently reserved"

# Update is part of the same authenticated server-management surface. Keep its
# deeper Portainer/exact-SHA/rollback contract authoritative without duplicating
# those assertions here.
subprocess.run(
    [sys.executable, str(ROOT / "server/scripts/test_setup_center_update.py")],
    cwd=ROOT,
    check=True,
)

print("Setup Center server control + exact-SHA Update contract: PASS")
