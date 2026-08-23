#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

def text(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")

controller = text("cmd/update-controller/main.go")
controller_test = text("cmd/update-controller/main_test.go")
ui = text("server/scripts/setup_center_update.py")
product = text("server/scripts/setup-center-product-server.py")
release = text("server/scripts/setup_center_release_status.py")
compose = text("server/portainer-current.yaml")
materializer = text("deploy/materialize-production-compose.py")
verifier = text("server/scripts/verify-production-compose.py")
publish = text(".github/workflows/publish-arm64-images.yml")
preflight = text(".github/workflows/arm64-portainer-preflight.yml")
configure = text("server/scripts/configure-portainer-update.sh")
reserved = text("cmd/router-agent/reserved_dynamic.go")
router_example = text("configs/router/router-agent.json.example")

for marker in (
    'defaultListen          = "127.0.0.1:8793"',
    'defaultPortainerURL    = "https://127.0.0.1:9443"',
    'Portainer Update is restricted to a loopback Portainer origin',
    'subtle.ConstantTimeCompare',
    'VerifyConnection:',
    'Portainer TLS certificate fingerprint changed',
    '"X-API-Key"',
    '"release-candidate.yml", "publish-arm64-images.yml", "production-release-compose.yml"',
    '"PullImage": true, "Prune": false',
    'preserveUpdater(target, previous)',
    'waitCoreHealthy(stack, 120*time.Second)',
    'automatic rollback also failed',
    '/api/admin/update/status',
    '/api/admin/update/check',
    '/api/admin/update/apply',
):
    assert marker in controller, f"update controller missing {marker!r}"

for forbidden in (
    'docker system prune',
    'docker compose',
    'InsecureSkipVerify: false',
    '0.0.0.0:8793',
):
    assert forbidden not in controller, f"update controller contains unsafe/fake marker {forbidden!r}"
# The updater must explicitly reject a Docker-socket mount in a candidate compose;
# mentioning the path in this validation is a safety invariant, not socket access.
assert '- /var/run/docker.sock' in controller, 'update controller no longer rejects Docker-socket mounts in candidate compose'

for marker in (
    'TestMaterializeExactSHAAndNoFloatingOldImages',
    'TestMaterializeRejectsDockerSocketBuildAndLatest',
    'TestMaterializeRequiresUpdaterService',
    'TestPreserveUpdaterKeepsOnlyOldUpdaterDuringPhaseOne',
    'TestStackEnvironmentFailsClosedWhenMissingOrInvalid',
    'TestComposeSHARejectsMixedPhaseOneEvenWithGeneratedHeader',
):
    assert marker in controller_test, f"update-controller Go tests missing {marker!r}"

for marker in (
    'Update Router VPN',
    '/api/admin/update/status',
    '/api/admin/update/check',
    '/api/admin/update/apply',
    "credentials:'same-origin'",
    'Setup Center is restarting during the update; reconnecting',
    'Apply verified SHA',
):
    assert marker in ui, f"Setup Center Update UI missing {marker!r}"
assert 'X-API-Key' not in ui and 'portainer-api.key' not in ui, "browser UI must never receive Portainer credentials"

for marker in (
    'UPDATE_BASE = "http://127.0.0.1:8793"',
    'UPDATE_PREFIX = "/api/admin/update"',
    '_proxy_update',
    '_require_auth()',
    'setup_center_update.py',
):
    assert marker in product, f"Setup Center Update proxy missing {marker!r}"

assert '"self_update_available": True' in release, "release status still claims Update is unavailable"
assert 'no Docker socket in Setup Center or update controller' in release

for marker in (
    'router-vpn-updater:',
    'ghcr.io/eabusham2/router-vpn-updater:',
    'ROUTER_VPN_UPDATE_LISTEN: 127.0.0.1:8793',
    '/opt/router-vpn/config:/etc/router-vpn:ro',
    '/opt/router-vpn/admin-state:/var/lib/router-vpn',
):
    assert marker in compose, f"production compose updater missing {marker!r}"
assert '/var/run/docker.sock' not in compose, "production updater gained Docker socket access"

for body, name in ((materializer, 'materializer'), (verifier, 'verifier')):
    assert 'updater' in body, f"production {name} does not bind updater to exact SHA"
    assert '/var/run/docker.sock' in body, f"production {name} does not explicitly reject Docker socket"

for marker in (
    'name: updater',
    'dockerfile: deploy/update-controller.Dockerfile',
    'image: router-vpn-updater',
):
    assert marker in publish, f"ARM64 image publication missing updater marker {marker!r}"
for marker in (
    'Build update controller image',
    'router-vpn-preflight-updater:arm64',
    'go test ./cmd/update-controller -count=1',
):
    assert marker in preflight, f"ARM64 preflight missing updater marker {marker!r}"

for marker in (
    '127.0.0.1|::1',
    'stty -echo',
    'chmod 600 "$KEY_TMP" "$PIN_TMP"',
    'portainer-api.key',
    'portainer-tls.sha256',
    'The API key remains server-side',
):
    assert marker in configure, f"private Portainer configuration missing {marker!r}"

assert '8793,' in reserved, "upgrade-time reserved control ports omit updater 8793"
assert '8793' in router_example, "fresh-install reserved control ports omit updater 8793"

print("Setup Center rollback-safe exact-SHA Update contract: PASS")
