# Router VPN — start here

Current entrypoints:

- Full setup/product guide: `docs/CURRENT-GUIDE.md`
- Current implementation boundaries: `docs/CURRENT-STATUS.md`
- Portainer stack: `server/portainer-current.yaml`
- ASUS forwarding helper: `router/asus-merlin-router-vpn-forwards.sh`
- Terminal manager: `server/manage.sh`
- Diagnostics: `server/scripts/doctor-current.sh`
- Raw mode catalog: `configs/client/modes.json`
- Logical app catalog: `configs/client/logical-modes.json`

## Normal deployment

```text
GitHub CI green
→ Portainer server/portainer-current.yaml
→ exact-SHA image-only server stack
→ verify init/finalizer + running services
→ private Setup Center :8786
→ ASUS helper
→ install/pair client
→ off-LAN real tunnel test
```

Normal Portainer environment:

```text
WAN_INTERFACE=eth0
LAN_CIDR=192.168.50.0/24
ADGUARD4=192.168.50.133
```

`ENDPOINT` is optional.

## Client downloads

Open the private Setup Center on the LAN:

```text
http://192.168.50.133:8786/
```

Client packages are GitHub-artifact-first. If the matching client artifact is unavailable, the AI Board compiles only the requested package locally. Private customization and build output are temporary and deleted after delivery.

PortableApps/PAF is not supported; normal Router VPN Portable ZIP x64/ARM64 is supported.

Never WAN-expose `1080`, `8786`, `8787`, `14444`, `9443`, SSH, Portainer, or AdGuard admin.
