# Router VPN — start here

Current entrypoints:

- Full setup/product guide: `docs/CURRENT-GUIDE.md`
- Current implementation/release boundaries: `docs/CURRENT-STATUS.md`
- Client linking/platform notes: `docs/CLIENT.md`
- Native app boundaries: `docs/NATIVE-APPS.md`
- Build/release details: `docs/BUILDS.md`
- Portainer stack: `server/portainer-current.yaml`
- ASUS forwarding helper: `router/asus-merlin-router-vpn-forwards.sh`
- Terminal manager: `server/manage.sh`
- Diagnostics: `server/scripts/doctor-current.sh`
- Raw mode catalog: `configs/client/modes.json`
- Logical app catalog: `configs/client/logical-modes.json`

## Release/deployment order

```text
requirements/source reconciliation
→ GitHub source/security/native/runtime gates
→ exact-SHA ARM64 images + one-SHA client release candidate
→ physical-device / off-LAN / visual / AI-provider / signing gates
→ deliberate exact-SHA Portainer production deploy
→ live smoke tests
→ inspect/revalidate ASUS forwarding
→ final regression matrix
```

Production is never promoted from an old release candidate merely because it once passed.

Normal Portainer environment:

```text
WAN_INTERFACE=eth0
LAN_CIDR=192.168.50.0/24
ADGUARD4=192.168.50.133
```

`ENDPOINT` is optional and normally left unset for auto-detection.

## Client downloads

Open the private Setup Center on the LAN:

```text
http://192.168.50.133:8786/
```

Generic client packages are GitHub-artifact-first. If the matching artifact is unavailable/unusable, the AI Board can compile only the requested generic package locally with the bounded fallback. The generic installer/Portable ZIP remains secret-free; link/import/pair private nodes separately after installation.

PortableApps/PAF is not supported; normal Router VPN Portable ZIP x64/ARM64 is supported.

## Private/public boundary

Never WAN-expose `1080`, `8786`, `8787`, `14444`, `9443`, SSH, Portainer or AdGuard admin. Setup Center Simple Methods may use only their documented public listeners; complex Router VPN stacks remain in the Router VPN app.

Real release claims require the documented physical/off-LAN/leak-negative/signing/production evidence. CI/source readiness alone is not final product completion.
