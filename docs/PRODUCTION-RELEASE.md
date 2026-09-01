# Router VPN exact-SHA production release

`server/portainer-current.yaml` is the tracked, image-only production **template/baseline**. It intentionally contains one previously approved exact runtime SHA so the tracked file is reproducible and validates as a real Compose file. It is not proof that its embedded SHA equals a newer source commit.

For a release, GitHub Actions workflow **Exact-SHA production compose** runs `deploy/materialize-production-compose.py` against that template and produces:

```text
RouterVPN-Portainer-<40-character-release-SHA>.yaml
RouterVPN-Portainer-<40-character-release-SHA>.yaml.sha256
```

The materializer changes only Router VPN custom GHCR image tags and `ROUTER_VPN_GITHUB_SHA`. It requires all tracked custom image references and broker provenance to start from one full SHA, preserves pinned third-party images, refuses moving/local-build production constructs, and verifies the generated output is entirely pinned to the requested release SHA.

## Release rule

Use a generated production compose only when all of these are true for the **same SHA**:

1. `main` points at that SHA.
2. Exact-head source/native/release workflows are green.
3. `Publish ARM64 Portainer images` succeeded for that SHA.
4. `Exact-SHA production compose` succeeded for that SHA.
5. The generated compose artifact checksum passes.
6. The generated file's Router VPN image tags and `ROUTER_VPN_GITHUB_SHA` all equal that SHA.
7. `server/scripts/verify-production-compose.py` accepts the generated YAML.

Do not deploy the tracked baseline file merely because it is named `portainer-current.yaml`, and do not deploy an older generated RC after `main` has moved.

## Portainer

For the deliberate release update, use the generated exact-SHA YAML as the Router VPN stack definition and preserve the normal deployment values:

```env
WAN_INTERFACE=eth0
LAN_CIDR=192.168.50.0/24
ADGUARD4=192.168.50.133
```

`ENDPOINT` remains optional and should normally be unset so endpoint detection can operate. Do not add a moving image tag or `build:` fallback. Do not WAN-forward private/admin ports (`1080`, `8786-8793`, `9443`, `14444`, `45999`, SSH, Portainer, or AdGuard admin).

## Automatic Portainer updates

The generated production stack includes a loopback-only update controller plus an automatic scheduler. The scheduler is enabled by default, waits two minutes after startup and checks hourly unless bounded environment overrides are supplied. A malformed explicit enable setting disables unattended updates.

The controller requires the same exact-SHA release/image/compose preconditions as a deliberate manual release, preserves the existing Portainer environment, keeps `Prune=false`, stores the previous exact compose before mutation, proves core health, updates itself last and restores the previous healthy stack on failure. Failed rollback remains durable `rolling-back` so restart reconciliation can continue; mixed image generations never count as one exact SHA. See `docs/AUTO-UPDATES.md`.

## Terminal manager

The terminal install/upgrade path uses the same generated release contract and rejects the tracked baseline. Example:

```bash
export ROUTER_VPN_PRODUCTION_COMPOSE=/absolute/path/RouterVPN-Portainer-<release-sha>.yaml
sudo -E bash server/manage.sh
```

`server/install.sh` and `server/upgrade.sh` call `server/scripts/verify-production-compose.py` before Docker. The verifier requires the generated exact-SHA header, exact Router VPN custom-image counts/pins, matching broker provenance, no moving Router VPN tag, and no production `build:`/remote Git context.

After the update, prove the one-shot init/finalizer exit cleanly, all expected long-running services stay running, Setup Center `/healthz` returns 200, the running image IDs/tags match the selected SHA, and the selected VPN path itself passes the separate live release matrix before calling the whole release complete.
