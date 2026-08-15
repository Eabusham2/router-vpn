# Use the current Router VPN stack

Use these files for the current implementation:

- **Guide:** `docs/CURRENT-GUIDE.md`
- **Status / source-vs-live boundary:** `docs/CURRENT-STATUS.md`
- **Client notes:** `docs/CLIENT.md`
- **Native apps:** `docs/NATIVE-APPS.md`
- **Build/release notes:** `docs/BUILDS.md`
- **Production release contract:** `docs/PRODUCTION-RELEASE.md`
- **Tracked Portainer template/baseline:** `server/portainer-current.yaml`
- **Exact-SHA production compose generator:** `.github/workflows/production-release-compose.yml` (`Exact-SHA production compose`)
- **Terminal manager (requires generated compose):** `server/manage.sh`
- **Generated-compose verifier:** `server/scripts/verify-production-compose.py`
- **macOS client installer/recovery path:** `client/install-macos-final.sh`
- **Linux client installer/recovery path:** `client/install-linux.sh`
- **Diagnostics:** `server/scripts/doctor-current.sh`
- **Logical app catalog:** `configs/client/logical-modes.json`
- **Raw runtime catalog:** `configs/client/modes.json`
- **Cross-platform native/client CI:** `.github/workflows/client-apps-ci.yml`
- **One-SHA release candidate:** `.github/workflows/release-candidate.yml`
- **Exact-SHA ARM64 image publisher:** `.github/workflows/publish-arm64-images.yml`

The tracked `server/portainer-current.yaml` is an image-only production **template/baseline**. Do not treat its embedded historical SHA as the current release merely because the filename says `current`. For a deliberate production release, use the `RouterVPN-production-compose-<sha>` artifact produced by **Exact-SHA production compose** for the same verified `main` SHA whose ARM64 images and release gates are green; verify its checksum and SHA pins as described in `docs/PRODUCTION-RELEASE.md`.

Terminal install/upgrade is fail-closed too: set `ROUTER_VPN_PRODUCTION_COMPOSE=/path/to/RouterVPN-Portainer-<sha>.yaml` before running `server/manage.sh`, `server/install.sh` or `server/upgrade.sh`. Those scripts verify the generated header, image pins and broker provenance and reject the tracked baseline.

The production server remains exact-SHA image-only. The AI Board local compile fallback is only for one requested **generic client package** when its matching GitHub artifact is unavailable/unusable; it is not a production-server source-build fallback.

Generic client packages contain no linked home-node secrets. Install the app once and link/import/pair private nodes separately.

Do not treat old copied tutorials, stale release candidates, moving image tags, browser/PWA shells, WSL execution, CSS readiness or generic Internet reachability as substitutes for the current native/product/path-proof contracts.
