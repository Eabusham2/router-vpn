# Router VPN — start here

Use only these current entrypoints:

- Full setup + mode guide: `docs/CURRENT-GUIDE.md`
- Current implementation boundaries: `docs/CURRENT-STATUS.md`
- Portainer stack: `server/portainer-current.yaml`
- Persistent ASUS Merlin WAN-forward helper: `router/asus-merlin-router-vpn-forwards.sh`
- Terminal install/update manager: `server/manage.sh`
- macOS client installer: `client/install-macos-final.sh`
- Linux client installer: `client/install-linux.sh`
- Router/AI-Board diagnostics: `server/scripts/doctor-current.sh`
- Mode source of truth: `configs/client/modes.json`
- Single cross-platform build workflow: `.github/workflows/build-all.yml`

## First install

Use the complete sequence in `docs/CURRENT-GUIDE.md`:

```text
Portainer home node
→ verify init/finalizer + running services
→ download private client bundle
→ install persistent ASUS Merlin WAN forwards
→ install/import client
→ choose DNS/mode/options
→ run optional checks + live off-LAN tests
```

The desktop WebGUI also opens the complete first-run onboarding automatically. Its progress is saved; **Finish** keeps it dismissed later; **Help & setup → Run full onboarding again** reopens it without erasing the saved router profile.

## Portainer

Deploy this repository using:

```text
server/portainer-current.yaml
```

Normal environment values:

```text
WAN_INTERFACE=eth0
LAN_CIDR=192.168.50.0/24
ADGUARD4=192.168.50.133
```

`ENDPOINT` is optional and may stay unset/blank for automatic public-IP detection.

The current stack preserves current-version profile credentials across normal redeploys. Older profile-engine layouts migrate once; after a migration, download/import the newly generated private client bundle once.

## Client bundle

On the home LAN:

```text
http://192.168.50.133:8786/router-vpn-client-bundle.zip
```

The ZIP includes the generated profiles plus:

```text
router/asus-merlin-router-vpn-forwards.sh
```

The default ASUS mapping uses **external TCP 80 → AI Board TCP 18080** for the ACME challenge. Do not WAN-expose `1080`, `8786`, `8787`, `9443`, SSH, Portainer, or AdGuard admin.

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

On the AI Board/Docker host:

```bash
sudo bash server/scripts/doctor-current.sh
```

On the ASUS router after installing the bundled helper:

```bash
/jffs/scripts/router-vpn-forward.sh status
```

The safe checks do not print private keys/passwords and do not pretend a live VPN handshake occurred. Live mode success requires an actual connection/health check from off-LAN.
