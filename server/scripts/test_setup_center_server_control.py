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
agent_dockerfile = text("deploy/router-agent.Dockerfile")

for marker in (
    'defaultAdminServerControlListen = "127.0.0.1:8792"',
    'subtle.ConstantTimeCompare',
    '/api/admin/server-control/stop',
    '/api/admin/server-control/emergency-stop',
    '/api/admin/server-control/resume',
    'serverControlInfrastructurePorts',
    '8793: true',
    'validateEmergencyPeerTeardown',
    'enforceEmergencyPeers',
    'emergencyReconcileLoop',
    'opMu      sync.Mutex',
    'remaining_peer_rows',
    'coverage_sources',
    's.setState(true, false)',
    's.setState(true, true)',
    'persisted policy could not be re-applied',
    'router-vpn server paused',
    'removeLivePeer(peer.Interface, peer.PublicKey)',
    'Resume restores ingress without rotating keys or deleting configuration',
):
    assert marker in control, f"server control missing {marker!r}"

for private_service in ('1080: true', '14444: true', '45999: true'):
    assert private_service not in control, f"Stop incorrectly preserves Router VPN service marker {private_service!r}"

for forbidden in (
    'docker system prune', 'docker stop', 'docker rm', '/var/run/docker.sock',
    '0.0.0.0:8792', 'policy drop', 'flush ruleset',
):
    assert forbidden not in control, f"server control contains unsafe marker {forbidden!r}"

# Emergency is a two-phase durable transaction: ordinary Stop must commit
# first, then both WG/AWG peer sources must prove zero peers, and only then may
# emergency=true be persisted. A restart must re-prove that stronger state.
emergency = control.split('func (s *adminServerControl) emergencyStop', 1)[1]
pause_at = emergency.find('s.setState(true, false)')
prove_at = emergency.find('enforceEmergencyPeers()')
emergency_at = emergency.find('s.setState(true, true)')
assert 0 <= pause_at < prove_at < emergency_at, 'Emergency Stop state/proof ordering regressed'
startup = control.split('func startAdminServerControlPlane()', 1)[1].split('func defaultServerControlState()', 1)[0]
for marker in ('if err := s.apply(); err != nil', 'if s.emergencyActive()', 'enforceEmergencyPeers()', 'go s.emergencyReconcileLoop()'):
    assert marker in startup, f"startup Emergency re-proof missing {marker!r}"
assert startup.find('if err := s.apply(); err != nil') < startup.find('http.NewServeMux()'), 'admin plane must not serve before persisted firewall state is re-applied'

for marker in (
    'Stop VPN', 'Emergency Stop', 'Resume VPN',
    '/api/admin/server-control/stop',
    '/api/admin/server-control/emergency-stop',
    '/api/admin/server-control/resume',
    "credentials:'same-origin'",
    'await window.refreshRouterVpnServerControl();alert(\'Emergency Stop incomplete',
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

for marker in ('command -v wg >/dev/null', 'command -v awg >/dev/null', '/usr/local/bin/awg'):
    assert marker in agent_dockerfile, f"agent image cannot prove Emergency Stop control coverage: missing {marker!r}"

# Update is part of the same authenticated server-management surface. Keep its
# deeper Portainer/exact-SHA/rollback contract authoritative without duplicating
# those assertions here.
subprocess.run(
    [sys.executable, str(ROOT / "server/scripts/test_setup_center_update.py")],
    cwd=ROOT,
    check=True,
)

print("Setup Center server control + exact-SHA Update contract: PASS")
