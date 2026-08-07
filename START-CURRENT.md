# Router VPN — start here

Use only these current entrypoints:

- Full current guide: `docs/CURRENT-GUIDE.md`
- Current implementation boundaries: `docs/CURRENT-STATUS.md`
- Portainer stack: `server/portainer-current.yaml`
- Terminal install/update manager: `server/manage.sh`
- macOS client installer: `client/install-macos-final.sh`
- Linux client installer: `client/install-linux.sh`
- Router diagnostics: `server/scripts/doctor-current.sh`
- Mode source of truth: `configs/client/modes.json`
- Single build workflow: `.github/workflows/build-all.yml`

## Portainer

Deploy this repository using:

```text
server/portainer-current.yaml
```

The current stack preserves current-version profile credentials across normal redeploys. Older profile-engine layouts migrate once; after a migration, download/import the newly generated private client bundle once.

## Terminal

First install or later update from the repository:

```bash
sudo bash server/manage.sh
```

## Client

macOS:

```bash
bash client/install-macos-final.sh "$PWD"
```

Linux:

```bash
sudo bash client/install-linux.sh "$PWD"
```

Then open:

```text
http://127.0.0.1:8788
```

## Verify

On the router/Docker host:

```bash
docker compose -f server/portainer-current.yaml config >/dev/null
sudo bash server/scripts/doctor-current.sh
```

The doctor does not print private keys/passwords.
