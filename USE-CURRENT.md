# Use the current Router VPN stack

Use these files for the current implementation:

- **Guide:** `docs/CURRENT-GUIDE.md`
- **Status:** `docs/CURRENT-STATUS.md`
- **Portainer:** `server/portainer-current.yaml`
- **Terminal install/update manager:** `server/manage.sh`
- **macOS client installer:** `client/install-macos-final.sh`
- **Linux client installer:** `client/install-linux.sh`
- **Diagnostics:** `server/scripts/doctor-current.sh`
- **Logical app catalog:** `configs/client/logical-modes.json`
- **Raw runtime catalog:** `configs/client/modes.json`
- **Primary all-platform build workflow:** `.github/workflows/build-all.yml`

The production server compose is exact-SHA image-only. The AI Board local compile fallback is for one requested client package when its matching GitHub artifact is unavailable.
