# Use the current Router VPN stack

Use these files for the current implementation:

- **Guide:** `docs/CURRENT-GUIDE.md`
- **Status / source-vs-live boundary:** `docs/CURRENT-STATUS.md`
- **Client notes:** `docs/CLIENT.md`
- **Native apps:** `docs/NATIVE-APPS.md`
- **Build/release notes:** `docs/BUILDS.md`
- **Portainer:** `server/portainer-current.yaml`
- **Terminal manager:** `server/manage.sh`
- **macOS client installer/recovery path:** `client/install-macos-final.sh`
- **Linux client installer/recovery path:** `client/install-linux.sh`
- **Diagnostics:** `server/scripts/doctor-current.sh`
- **Logical app catalog:** `configs/client/logical-modes.json`
- **Raw runtime catalog:** `configs/client/modes.json`
- **Cross-platform native/client CI:** `.github/workflows/client-apps-ci.yml`
- **One-SHA release candidate:** `.github/workflows/release-candidate.yml`
- **Exact-SHA ARM64 image publisher:** `.github/workflows/publish-arm64-images.yml`

The production server compose is exact-SHA image-only. The AI Board local compile fallback is only for one requested **generic client package** when its matching GitHub artifact is unavailable/unusable; it is not a production-server source-build fallback.

Generic client packages contain no linked home-node secrets. Install the app once and link/import/pair private nodes separately.

Do not treat old copied tutorials, stale release candidates, moving image tags, browser/PWA shells, WSL execution, CSS readiness or generic Internet reachability as substitutes for the current native/product/path-proof contracts.
