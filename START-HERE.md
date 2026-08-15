# Router VPN — start here

Use these current sources:

1. **Authoritative setup/product guide:** `docs/CURRENT-GUIDE.md`
2. **Current implementation status and honest limitations:** `docs/CURRENT-STATUS.md`
3. **Client/platform notes:** `docs/CLIENT.md`
4. **Build/artifact details:** `docs/BUILDS.md`
5. **Windows Portable ZIP:** `docs/WINDOWS-PORTABLE.md`
6. **Raw runtime-mode details:** `docs/MODES.md`
7. **Exact-SHA production release contract:** `docs/PRODUCTION-RELEASE.md`
8. **Tracked Portainer template/baseline:** `server/portainer-current.yaml`
9. **Release compose workflow:** `Exact-SHA production compose`

The tracked Portainer file is a reproducible image-only **template/baseline**, not the deploy target for whatever commit happens to be newest. For production, use the generated `RouterVPN-production-compose-<sha>` artifact for the exact verified `main` SHA, after the same-SHA ARM64 image publisher and release gates are green. Verify its checksum and pins per `docs/PRODUCTION-RELEASE.md`.

The app presents 16 logical modes while the server retains 20 raw runtime profiles internally. Do not use an older copied tutorial, obsolete deployment Compose file, or the tracked baseline as a substitute for the generated exact-SHA release artifact.
